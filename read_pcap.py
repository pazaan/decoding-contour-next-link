#!/usr/bin/env python

import sys
import binascii
import pyshark # pip install pyshark
from bitstring import BitArray, BitStream, pack # pip install bigstring
import crc16 # pip install crc16
import Crypto.Cipher.AES # pip install PyCrypto

INCOMING_ENDPOINT = 0x83 # This is the incoming endpoint we want data from
OUTGOING_ENDPOINT = 0x04 # This is the outgoing endpoint we want data from
USB_PACKET_SIZE = 60

class MedtronicSession:
    radioChannel = None
    stickSerial = None
    pumpSerial = None

    # TODO - this is Lennart's KEY. Other people's keys could be different
    @property
    def KEY( self ):
        return binascii.unhexlify( "57833334130906A587B7A0437BC28A69" )

    @property
    def IV( self ):
        return binascii.unhexlify( "{0:02x}833334130906A587B7A0437BC28A69".format( self.radioChannel ) )

class BayerBinaryMessage( object ):
    messageHandler = None
    IN = 0x0
    OUT = 0x1

    @property
    def header( self ):
        self.stream.bytepos = 0x0
        return self.stream.readlist( '2*bytes:1' )

    @property
    def pumpId( self ):
        self.stream.bytepos = 0x2
        return self.stream.read( 'bytes:6' )

    @property
    def unknownBytes1( self ):
        self.stream.bytepos = 0x8
        return self.stream.read( 'int:80' ) # This is 80 bits of data, 10 bytes

    @property
    def messageType( self ):
        self.stream.bytepos = 0x12
        return self.stream.read( 'uint:8' )

    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x13
        return self.stream.read( 'uintle:32' ) # Assuming for now it's a regular int

    @property
    def unknownBytes2( self ):
        self.stream.bytepos = 0x17
        return self.stream.read( 'int:40' ) # This is 40 bits of data, 5 bytes

    @property
    def messageSize( self ):
        self.stream.bytepos = 0x1c
        return self.stream.read( 'uintle:32' ) # Assuming for now it's a regular int

    @property
    def messageChecksum( self ):
        self.stream.bytepos = 0x20
        return self.stream.read( 'uintle:8' )

    @property
    def payload( self ):
        # get size here, because properties advance the stream pointer, and we want it to
        # stay set when we read the payload
        payloadSize = self.messageSize
        self.stream.bytepos = 0x21
        return self.stream.read( 'bytes:%d' % ( payloadSize ) )

    @classmethod
    def MessageFactory( cls, stream, messageDirection, pumpSession ):
        stream.bytepos = 0x0
        if( stream.readlist( '2*bytes:1' ) != [ 'Q', '\x03' ] ):
            return None

        stream.bytepos = 0x12
        messageType = stream.read( 'uint:8' )

        print "MESSAGE TYPE: %s, Direction: %s" % ( messageType, messageDirection )
        if( messageType == 0x10 and messageDirection == BayerBinaryMessage.OUT ):
            return MtInitStickMessage( stream )
        elif( messageType == 0x10 and messageDirection == BayerBinaryMessage.IN ):
            return CcittMessage( stream )
        elif( messageType == 0x14 and messageDirection == BayerBinaryMessage.IN ):
            return MtGetAttachedPumpMessage( stream )
        elif( messageType == 0x12 ):
            stream.bytepos = 0x21
            medtronicSendType = stream.read( 'uint:8' )

            if( medtronicSendType == 0x03 ):
                return MtFindPump( stream, pumpSession )
            elif( medtronicSendType == 0x05 ):
                return MtSendPump( stream, pumpSession )
        elif( messageType == 0x81 ):
            return MtPumpAck( stream )
        elif( messageType == 0x80 ):
            return MtPumpResponse( stream, pumpSession )
        elif( ( stream.length / 8 ) > 33 ):
            return MtStandardMessage( stream, pumpSession )
        else:
            return BayerBinaryMessage( stream )

    def __init__( self, stream ):
        self.stream = stream

        if( self.header != [ 'Q', '\x03' ] ):
            return

        # If our Unknown Bytes are ever anything other than padded nulls, we want to know about it!
        self.checkNullBytes( 'unknownBytes1' )
        self.checkNullBytes( 'unknownBytes2' )

        expectedMessageSize = 0x21 + self.messageSize
        if( ( self.stream.length / 8 ) != expectedMessageSize ):
            print "Message size mismatch. Expecting message to be '%d' bytes, this stream has '%d' bytes" % ( expectedMessageSize, ( self.stream.length / 8 ) )
            raise Exception

        # Validate the checksum
        calcCrc = self.makeMessageCrc() # only calculate it once for the compare and the print
        if( calcCrc != self.messageChecksum ):
            print "Message checksum doesn't match. Expected '%#x', calculated '%#x'" % ( self.messageChecksum, calcCrc )
            raise Exception

    def checkNullBytes( self, field ):
        if( getattr( self, field ) != 0 ):
            print '*** SOMETHING NEW! %s is more than it seems' % ( field )
            raise Exception

    def makeMessageCrc( self ):
        # unpack is the same as readlist, but starts from the beginning of the stream
        bytes = self.stream.unpack( '%s*uint:8' % ( self.stream.length / 8 ) )
        # The 33rd byte is the checksum itself, and shouldn't be included in the message checksum
        del bytes[32]
        return sum(bytes) & 0xff

    def __str__( self ):
        if( self.header == [ 'Q', '\x03' ] ):
            # If we have an attached message handler, use it's string method instead
            if( self.messageHandler is not None ):
                payload = self.messageHandler
            else:
                payload = self.payload.encode('hex')

            # Binary Bayer message
            return '%s, %s, %s, %#x, %d, %#x, %d, %#x' % ( self.header, self.pumpId, self.unknownBytes1, self.messageType, self.sequenceNumber, self.unknownBytes2, self.messageSize, self.messageChecksum )
        else:
            return '%s' % ( self.header )

class MtInitStickMessage( BayerBinaryMessage ):
    def __str__( self ):
        self.stream.bytepos = 0x21
        return "%s\n*** Hashed payload? %s\nSize: %d" % ( BayerBinaryMessage.__str__(self), self.stream.read( 'bytes:32' ).encode('hex'), ( len( self.stream ) / 8 ) - 0x21 )

class MtGetAttachedPumpMessage( BayerBinaryMessage ):
    @property
    def delimiter1( self ):
        self.stream.bytepos = 0x21
        return self.stream.read( 'uint:24' )

    @property
    def delimiter2( self ):
        self.stream.bytepos = 0x29
        return self.stream.read( 'uint:24' )

    @property
    def stickIdentifier( self ):
        self.stream.bytepos = 0x24
        return self.stream.read( 'uint:16' )

    @property
    def stickSerial( self ):
        self.stream.bytepos = 0x26
        return self.stream.read( 'uint:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x2c
        return self.stream.read( 'uint:16' )

    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x2e
        return self.stream.read( 'uint:24' )

    @property
    def unknownBytes( self ):
        self.stream.bytepos = 0x31
        return self.stream.read( 'bytes:3' ).encode( 'hex' )

    def __init__( self, stream ):
        BayerBinaryMessage.__init__( self, stream )

        # Response looks like this:
        # 0023f7 0682 <stickID in Big Endian> 0023f7 45ee <pumpID in Big Endian> <Unknown bytes>
        assert self.stickIdentifier == MtStandardMessage.STICK_IDENTIFIER
        assert self.pumpIdentifier == MtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter1 == MtStandardMessage.DELIMITER
        assert self.delimiter2 == MtStandardMessage.DELIMITER

    def __str__( self ):
        return "%s\nStick serial: '%d', Pump serial: '%d', Unknown Bytes: '%s'" % ( BayerBinaryMessage.__str__(self), self.stickSerial, self.pumpSerial, self.unknownBytes )

class CcittMessage( BayerBinaryMessage ):
    @property
    def ccittPayload( self ):
        self.stream.bytepos = 0x21
        return self.stream.read( 'bytes:%d' % ( ( self.stream.length / 8 ) - 0x21 - 2 ) )

    @property
    def ccitt( self ):
        self.stream.bytepos = ( self.stream.length / 8 ) - 2
        return self.stream.read( 'uintle:16' )

    def __init__( self, stream ):
        BayerBinaryMessage.__init__( self, stream )

        calcCcitt = self.makeMessageCcitt()
        if( calcCcitt != self.ccitt ):
            print "CRC-CCITT doesn't match. Expected '%#x', calculated '%#x'" % ( self.ccitt, calcCcitt )
            raise Exception
        return

    def __str__( self ):
        return "%s\nCCITT_PAYLOAD: '%s'" % ( BayerBinaryMessage.__str__(self), self.ccittPayload.encode('hex') )

    def makeMessageCcitt( self ):
        crc = crc16.crc16xmodem( self.ccittPayload, 0xffff )
        return crc & 0xffff

class MtStandardMessage( CcittMessage ):
    STICK_IDENTIFIER = 0x0682
    PUMP_IDENTIFIER = 0x45ee
    DELIMITER = 0x0023f7

    @property
    def medtronicHeader( self ):
        self.stream.bytepos = 0x21
        return self.stream.read( 'bytes:1' )

    @property
    def medtronicMessageSize( self ):
        self.stream.bytepos = 0x22
        return self.stream.read( 'uint:8' )

    def pad(self, x, n=16):
        p = n - (len(x) % n)
        return x + chr(p) * p

    # Encrpytion equivalent to Java's AES/CFB/NoPadding mode
    def encrypt( self, clear ):
        cipher = Crypto.Cipher.AES.new(
            key=pumpSession.KEY,
            mode=Crypto.Cipher.AES.MODE_CFB,
            IV=pumpSession.IV,
            segment_size=128
        )

        encrypted = cipher.encrypt(self.pad(clear))[0:len(clear)]
        return encrypted

    # Decryption equivalent to Java's AES/CFB/NoPadding mode
    def decrypt( self, encrypted ):
        cipher = Crypto.Cipher.AES.new(
            key=pumpSession.KEY,
            mode=Crypto.Cipher.AES.MODE_CFB,
            IV=pumpSession.IV,
            segment_size=128
        )

        decrypted = cipher.decrypt(self.pad(encrypted))[0:len(encrypted)]
        return decrypted

    def __init__( self, stream, pumpSession ):
        CcittMessage.__init__( self, stream )

        # The medtronicMessage size includes its header and the size byte
        assert self.medtronicMessageSize == len( self.payload ) - 2

class MtFindPump( MtStandardMessage ):
    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x23
        return self.stream.read( 'uint:8' )

    @property
    def radioChannel( self ):
        self.stream.bytepos = 0x24
        return self.stream.read( 'uint:8' )

    @property
    def unknownBytes( self ):
        self.stream.bytepos = 0x25
        return self.stream.read( 'bytes:8' )

    @property
    def stickSerial( self ):
        self.stream.bytepos = 0x2d
        return self.stream.read( 'uintle:24' )

    @property
    def stickIdentifier( self ):
        self.stream.bytepos = 0x30
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter1( self ):
        self.stream.bytepos = 0x32
        return self.stream.read( 'uintle:24' )

    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x35
        return self.stream.read( 'uintle:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x38
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter2( self ):
        self.stream.bytepos = 0x3a
        return self.stream.read( 'uintle:24' )

    def __init__( self, stream, pumpSession ):
        MtStandardMessage.__init__( self, stream, pumpSession )

        assert self.stickIdentifier == MtStandardMessage.STICK_IDENTIFIER
        assert self.pumpIdentifier == MtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter1 == MtStandardMessage.DELIMITER
        assert self.delimiter2 == MtStandardMessage.DELIMITER
        assert self.stickSerial == pumpSession.stickSerial
        assert self.pumpSerial == pumpSession.pumpSerial

    def __str__( self ):
        return "%s\nseqNo: %d, channel: %d, unknownBytes: '%s', Stick serial: %d, Pump serial: %d" % ( CcittMessage.__str__(self), self.sequenceNumber, self.radioChannel, self.unknownBytes.encode('hex'), self.stickSerial, self.pumpSerial )

class MtSendPump( MtStandardMessage ):
    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x23
        return self.stream.read( 'uintle:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x26
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter( self ):
        self.stream.bytepos = 0x28
        return self.stream.read( 'uintle:24' )

    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x2b
        return self.stream.read( 'uint:8' )

    @property
    def unknownByte( self ):
        self.stream.bytepos = 0x2c
        return self.stream.read( 'bytes:1' )

    @property
    def payloadSize( self ):
        self.stream.bytepos = 0x2d
        return self.stream.read( 'uintle:8' )

    @property
    def requestBody( self ):
        # get size here, because properties advance the stream pointer, and we want it to
        # stay set when we read the payload
        payloadSize = self.payloadSize
        self.stream.bytepos = 0x2e
        return self.stream.read( 'bytes:%d' % ( payloadSize ) )

    def __init__( self, stream, pumpSession ):
        MtStandardMessage.__init__( self, stream, pumpSession )

        assert self.pumpIdentifier == MtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter == MtStandardMessage.DELIMITER
        assert ( 0x2e + self.payloadSize ) == ( ( self.stream.length / 8 ) - 2 ) # minus 2 bytes for the CCITT
        assert self.pumpSerial == pumpSession.pumpSerial

    def __str__( self ):
        return "%s\nseqNo: %d, unknownByte: '%s', Pump serial: %d\nDecrpytped Payload: '%s'" % ( CcittMessage.__str__(self), self.sequenceNumber, self.unknownByte.encode('hex'), self.pumpSerial , self.decrypt( self.requestBody ).encode('hex'))

class MtPumpAck( MtStandardMessage ):
    @property
    def commandResponseCode( self ):
        self.stream.bytepos = 0x23
        return self.stream.read( 'uintle:16' )

    @property
    def unknownBytes( self ):
        self.stream.bytepos = 0x25
        return self.stream.read( 'bytes:7' )

    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x2c
        return self.stream.read( 'uint:8' )

    @property
    def unknownByte( self ):
        self.stream.bytepos = 0x2d
        return self.stream.read( 'bytes:1' )

    def __init__( self, stream ):
        MtStandardMessage.__init__( self, stream, pumpSession )

        if( self.medtronicMessageSize > 4 ):
            assert self.commandResponseCode == 1024
        else:
            assert self.commandResponseCode == 0

    def __str__( self ):
        if( self.medtronicMessageSize > 4 ):
            return "%s\nseqNo: %d, unknownBytes: %s, unknownByte: %s" % ( CcittMessage.__str__(self), self.sequenceNumber, self.unknownBytes.encode('hex'), self.unknownByte.encode('hex'))
        else:
            return "No extra data"

class MtPumpResponse( MtStandardMessage ):
    @property
    def commandResponseCode( self ):
        self.stream.bytepos = 0x23
        return self.stream.read( 'uintle:16' )

    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x25
        return self.stream.read( 'uintle:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x28
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter1( self ):
        self.stream.bytepos = 0x2a
        return self.stream.read( 'uintle:24' )

    @property
    def stickSerial( self ):
        self.stream.bytepos = 0x2d
        return self.stream.read( 'uintle:24' )

    @property
    def stickIdentifier( self ):
        self.stream.bytepos = 0x30
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter2( self ):
        self.stream.bytepos = 0x32
        return self.stream.read( 'uintle:24' )

    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x35
        return self.stream.read( 'uint:8' )

    @property
    def requestBody( self ):
        # get size here, because properties advance the stream pointer, and we want it to
        # stay set when we read the payload
        payloadSize = self.medtronicMessageSize - 21
        self.stream.bytepos = 0x36
        return self.stream.read( 'bytes:%d' % ( payloadSize ) )

    def __init__( self, stream, pumpSession ):
        MtStandardMessage.__init__( self, stream, pumpSession )

        # Sometimes response is 1024 (for the channel init) of 0000 (for a failed negotiation). This has different things
        assert self.commandResponseCode == 0 or self.commandResponseCode == 1536 or self.commandResponseCode == 1024

        if( self.commandResponseCode == 1536 ):
            assert self.pumpIdentifier == MtStandardMessage.PUMP_IDENTIFIER
            assert self.pumpSerial == pumpSession.pumpSerial
            assert self.stickIdentifier == MtStandardMessage.STICK_IDENTIFIER
            assert self.stickSerial == pumpSession.stickSerial
            assert self.delimiter1 == MtStandardMessage.DELIMITER
            assert self.delimiter2 == MtStandardMessage.DELIMITER

    def __str__( self ):
        if( self.commandResponseCode == 1536 ):
            return "%s\nseqNo: %d, Stick serial: %d, Pump serial: %d\nDecrpytped Payload: '%s'" % ( CcittMessage.__str__(self), self.sequenceNumber, self.stickSerial, self.pumpSerial , self.decrypt( self.requestBody ).encode('hex'))
        else:
            return "Haven't decoded this one yet"

if __name__ == '__main__':
    cap = pyshark.FileCapture( sys.argv[1] )

    messageBuffer = BitStream()

    i = 0
    pumpSession = MedtronicSession()

    for packet in cap:
        # Make sure the data is coming from one of the USB endpoints we care about.
        # Skip anything else
        usbEndpoint = int( packet.usb.endpoint_number, 16 )

        if( usbEndpoint != INCOMING_ENDPOINT and
            usbEndpoint != OUTGOING_ENDPOINT ):
            continue

        usbBuffer = BitStream('0x%s' % ( packet.data.usb_capdata.replace( ':', '' ) ) )
        usbHeader = usbBuffer.readlist( 'bytes:3, uint:8' )

        # Validate the header
        if( usbEndpoint == OUTGOING_ENDPOINT and usbHeader[0].encode( 'hex' ) != '000000' ):
            print 'Unexpected USB Header. Expected "0x000000", got "0x%s".' % ( usbHeader[0].encode( 'hex' ) )
            raise Exception
        if( usbEndpoint == INCOMING_ENDPOINT and usbHeader[0] != 'ABC' ):
            print 'Unexpected USB Header. Expected "0x414243", got "0x%s".' % ( usbHeader[0].encode( 'hex' ) )
            raise Exception

        messageBuffer.append( usbBuffer.read( usbHeader[1] * 8 ) )

        # Clear the messageBuffer if we have a full message
        # TODO - we need to be able to figure out if all 60 bytes are conusumed, but it's the end of the message
        if( usbHeader[1] < USB_PACKET_SIZE ):
            print >> sys.stderr, 'Message %s' % ( 'OUT' if usbEndpoint == OUTGOING_ENDPOINT else 'IN' )
            print >> sys.stderr, 'Hex: %s' % ( messageBuffer.hex )
            # TODO - make a bayerMessage to also handle standard command sequences and ASTM messages
            if( messageBuffer.bytes[0:2] != 'Q\x03' ):
                print >> sys.stderr, 'String: %s\n' % ( messageBuffer.bytes )
            else:
                msg = BayerBinaryMessage.MessageFactory( messageBuffer,
                    BayerBinaryMessage.OUT if usbEndpoint == OUTGOING_ENDPOINT else BayerBinaryMessage.IN, pumpSession )
                if( msg is not None ):
                    if( isinstance( msg, MtGetAttachedPumpMessage ) ):
                        pumpSession.pumpSerial = msg.pumpSerial
                        pumpSession.stickSerial = msg.stickSerial
                    elif( isinstance( msg, MtFindPump ) ):
                        pumpSession.radioChannel = msg.radioChannel
                    print msg
                    print

            messageBuffer.clear()
            i+=1

    print "Processed %d messages" % ( i )
