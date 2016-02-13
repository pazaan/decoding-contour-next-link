#!/usr/bin/env python

import sys
import binascii
import pyshark # pip install pyshark
from bitstring import BitArray, BitStream, pack # pip install bigstring
import crc16 # pip install crc16

INCOMING_ENDPOINT = 0x83 # This is the incoming endpoint we want data from
OUTGOING_ENDPOINT = 0x04 # This is the outgoing endpoint we want data from
USB_PACKET_SIZE = 60

class mtInitStickMessage( object ):
    def __init__( self, stream ):
        self.stream = stream

    def __str__( self ):
        return "*** Hashed payload? %s" % ( self.stream.hex )

class mtGetAttachedPumpMessage( object ):
    @property
    def delimiter1( self ):
        self.stream.bytepos = 0x0
        return self.stream.read( 'uint:24' )

    @property
    def delimiter2( self ):
        self.stream.bytepos = 0x8
        return self.stream.read( 'uint:24' )

    @property
    def stickIdentifier( self ):
        self.stream.bytepos = 0x3
        return self.stream.read( 'uint:16' )

    @property
    def stickSerial( self ):
        self.stream.bytepos = 0x5
        return self.stream.read( 'uint:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x0b
        return self.stream.read( 'uint:16' )

    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0xd
        return self.stream.read( 'uint:24' )

    @property
    def unknownBytes( self ):
        self.stream.bytepos = 0x10
        return self.stream.read( 'bytes:3' ).encode( 'hex' )

    def __init__( self, stream ):
        self.stream = stream

        # Response looks like this:
        # 0023f7 0682 <stickID in Big Endian> 0023f7 45ee <pumpID in Big Endian> <Unknown bytes>
        assert self.stickIdentifier == mtStandardMessage.STICK_IDENTIFIER
        assert self.pumpIdentifier == mtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter1 == mtStandardMessage.DELIMITER
        assert self.delimiter2 == mtStandardMessage.DELIMITER

    def __str__( self ):
        return "Stick serial: '%d', Pump serial: '%d', Unknown Bytes: '%s'" % ( self.stickSerial, self.pumpSerial, self.unknownBytes )

class ccittMessage( object ):
    @property
    def payload( self ):
        self.stream.bytepos = 0x0
        return self.stream.read( 'bytes:%d' % ( ( self.stream.length / 8 ) - 2 ) )

    @property
    def ccitt( self ):
        self.stream.bytepos = ( self.stream.length / 8 ) - 2
        return self.stream.read( 'uintle:16' )

    def __init__( self, stream ):
        self.stream = stream

        calcCcitt = self.makeMessageCcitt()
        if( calcCcitt != self.ccitt ):
            print "CRC-CCITT doesn't match. Expected '%#x', calculated '%#x'" % ( self.ccitt, calcCcitt )
            raise Exception
        return

    def __str__( self ):
        return self.payload.encode( 'hex' )

    def makeMessageCcitt( self ):
        crc = crc16.crc16xmodem( self.payload, 0xffff )
        return crc & 0xffff

class mtStandardMessage( ccittMessage ):
    STICK_IDENTIFIER = 0x0682
    PUMP_IDENTIFIER = 0x45ee
    DELIMITER = 0x0023f7

    @property
    def header( self ):
        self.stream.bytepos = 0x0
        return self.stream.read( 'bytes:1' )

    @property
    def messageSize( self ):
        self.stream.bytepos = 0x1
        return self.stream.read( 'uint:8' )

    def __init__( self, stream ):
        ccittMessage.__init__( self, stream )

        assert self.messageSize == len( self.payload )

class mtFindPump( mtStandardMessage ):
    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x2
        return self.stream.read( 'uint:8' )

    @property
    def radioChannel( self ):
        self.stream.bytepos = 0x3
        return self.stream.read( 'uint:8' )

    @property
    def unknownBytes( self ):
        self.stream.bytepos = 0x4
        return self.stream.read( 'bytes:8' )

    @property
    def stickSerial( self ):
        self.stream.bytepos = 0x0c
        return self.stream.read( 'uintle:24' )

    @property
    def stickIdentifier( self ):
        self.stream.bytepos = 0x0f
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter1( self ):
        self.stream.bytepos = 0x11
        return self.stream.read( 'uintle:24' )

    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x14
        return self.stream.read( 'uintle:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x17
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter2( self ):
        self.stream.bytepos = 0x19
        return self.stream.read( 'uintle:24' )

    def __init__( self, stream ):
        mtStandardMessage.__init__( self, stream )

        assert self.stickIdentifier == mtStandardMessage.STICK_IDENTIFIER
        assert self.pumpIdentifier == mtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter1 == mtStandardMessage.DELIMITER
        assert self.delimiter2 == mtStandardMessage.DELIMITER
        # TODO - should assert stick and pump serial

    def __str__( self ):
        return "seqNo: %d, channel: %d, unknownBytes: '%s', Stick serial: %d, Pump serial: %d" % ( self.sequenceNumber, self.radioChannel, self.unknownBytes.encode('hex'), self.stickSerial, self.pumpSerial )

class mtSendPump( mtStandardMessage ):
    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x2
        return self.stream.read( 'uintle:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x5
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter( self ):
        self.stream.bytepos = 0x7
        return self.stream.read( 'uintle:24' )

    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x0a
        return self.stream.read( 'uint:8' )

    @property
    def unknownByte( self ):
        self.stream.bytepos = 0x0b
        return self.stream.read( 'bytes:1' )

    @property
    def payloadSize( self ):
        self.stream.bytepos = 0x0c
        return self.stream.read( 'uintle:8' )

    @property
    def requestBody( self ):
        # get size here, because properties advance the stream pointer, and we want it to
        # stay set when we read the payload
        payloadSize = self.payloadSize
        self.stream.bytepos = 0x0d
        return self.stream.read( 'bytes:%d' % ( payloadSize ) )

    def __init__( self, stream ):
        mtStandardMessage.__init__( self, stream )

        assert self.pumpIdentifier == mtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter == mtStandardMessage.DELIMITER
        assert ( 0x0d + self.payloadSize ) == ( ( self.stream.length / 8 ) - 2 ) # minus 2 bytes for the CCITT
        # TODO - should assert pump serial

    def __str__( self ):
        return "seqNo: %d, unknownByte: '%s', Pump serial: %d\nHashed command? %s" % ( self.sequenceNumber, self.unknownByte.encode('hex'), self.pumpSerial , self.requestBody.encode('hex'))

class mtPumpAck( mtStandardMessage ):
    @property
    def pumpSerial( self ):
        self.stream.bytepos = 0x2
        return self.stream.read( 'uintle:24' )

    @property
    def pumpIdentifier( self ):
        self.stream.bytepos = 0x5
        return self.stream.read( 'uintle:16' )

    @property
    def delimiter( self ):
        self.stream.bytepos = 0x7
        return self.stream.read( 'uintle:24' )

    @property
    def sequenceNumber( self ):
        self.stream.bytepos = 0x0a
        return self.stream.read( 'uint:8' )

    @property
    def unknownByte( self ):
        self.stream.bytepos = 0x0b
        return self.stream.read( 'bytes:1' )

    @property
    def payloadSize( self ):
        self.stream.bytepos = 0x0c
        return self.stream.read( 'uintle:8' )

    @property
    def requestBody( self ):
        # get size here, because properties advance the stream pointer, and we want it to
        # stay set when we read the payload
        payloadSize = self.payloadSize
        self.stream.bytepos = 0x0d
        return self.stream.read( 'bytes:%d' % ( payloadSize ) )

    def __init__( self, stream ):
        mtStandardMessage.__init__( self, stream )

        assert self.pumpIdentifier == mtStandardMessage.PUMP_IDENTIFIER
        assert self.delimiter == mtStandardMessage.DELIMITER
        assert ( 0x0d + self.payloadSize ) == ( ( self.stream.length / 8 ) - 2 ) # minus 2 bytes for the CCITT
        # TODO - should assert pump serial

    def __str__( self ):
        return "seqNo: %d, unknownByte: '%s', Pump serial: %d\nHashed command? %s" % ( self.sequenceNumber, self.unknownByte.encode('hex'), self.pumpSerial , self.requestBody.encode('hex'))

class bayerBinaryMessage( object ):
    messageHandler = None

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

        # Attach a Metronic message handler
        if( self.messageType == 0x10 ):
            if( self.messageSize == 32 ):
                # The outgoing 0x10 message is not a CCITT message, and is 32 bytes long
                self.messageHandler = mtInitStickMessage( pack( 'bytes:%d' % ( len(self.payload) ), self.payload ) )
            else:
                self.messageHandler = ccittMessage( pack( 'bytes:%d' % ( len(self.payload) ), self.payload ) )
        elif ( self.messageType == 0x14 and self.messageSize > 0 ):
            # The outgoing 0x14 message has no payload
            self.messageHandler = mtGetAttachedPumpMessage( pack( 'bytes:%d' % ( len(self.payload) ), self.payload ) )
        elif ( len( self.payload ) > 0 ):
            if( self.messageType == 0x12 ):
                if( self.payload[0] == '\x03' ):
                    self.messageHandler = mtFindPump( pack( 'bytes:%d' % ( len(self.payload) ), self.payload ) )
                elif( self.payload[0] == '\x05' ):
                    self.messageHandler = mtSendPump( pack( 'bytes:%d' % ( len(self.payload) ), self.payload ) )
            else:
                self.messageHandler = mtStandardMessage( pack( 'bytes:%d' % ( len(self.payload) ), self.payload ) )

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
            return '%s, %s, %s, %#x, %d, %#x, %d, %#x\n%s' % ( self.header, self.pumpId, self.unknownBytes1, self.messageType, self.sequenceNumber, self.unknownBytes2, self.messageSize, self.messageChecksum, payload )
        else:
            return '%s' % ( self.header )

    def printDecodeProgress( self ):
        KNOWN = '\033[92m'
        GUESS = '\033[93m'
        UNKNOWN = '\033[91m'
        NOCOLOUR = '\033[0m'
        sys.stdout.write( KNOWN + self.stream.bytes[0:0x8].encode('hex') + UNKNOWN + self.stream.bytes[0x8:0x12].encode('hex') + KNOWN + self.stream.bytes[0x12:0x14].encode('hex') + GUESS + self.stream.bytes[0x15:0x18].encode('hex') + UNKNOWN + self.stream.bytes[0x17:0x1c].encode('hex') + KNOWN + self.stream.bytes[0x1c:0x1d].encode('hex') + GUESS + self.stream.bytes[0x1d:0x20].encode('hex') + KNOWN + self.stream.bytes[0x20:0x21].encode('hex') + NOCOLOUR )

        #if( self.messageHandler is not None ):
        if( False ):
            progress = messageHandler.printDecodeProgress
        else:
            print

cap = pyshark.FileCapture( sys.argv[1] )

messageBuffer = BitStream()

i = 0

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
            msg = bayerBinaryMessage( messageBuffer )
            #msg.printDecodeProgress()
            print msg
            print

        messageBuffer.clear()
        i+=1

print "Processed %d messages" % ( i )
