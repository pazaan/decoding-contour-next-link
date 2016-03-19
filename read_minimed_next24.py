#!/usr/bin/env python

import hid # pip install hidapi - Platform independant
import astm # pip install astm
from transitions import Machine # pip install transitions
import struct
import pprint
import curses.ascii
import binascii
import sys
import time
import crc16
import Crypto.Cipher.AES # pip install PyCrypto

class TimeoutException( Exception ):
    pass

class ChecksumException( Exception ):
    pass

class UnexpectedMessageException( Exception ):
    pass

class UnexpectedStateException( Exception ):
    pass

class NegotiationException( Exception ):
    pass

class MedtronicSession:
    # FIXME - hardcoded for Lennart's pump
    HMAC = 'e28fe4e5cf3c1eb6d6a2ec5a093093d4f397237dc60b3f2c1ef64f31e32077c4'
    linkMAC = 1055866 + 0x0023F70682000000
    pumpMAC = 1057941 + 0x0023F745EE000000
    radioChannel = None
    bayerSequenceNumber = 1
    minimedSequenceNumber = 1

    def __init__( self, hexKey='57833334130906a587b7a0437bc28a69' ):
        self.hexKey = hexKey

    @property
    def KEY( self ):
        return binascii.unhexlify( self.hexKey )

    @property
    def IV( self ):
        return binascii.unhexlify( "{0:02x}{1}".format( self.radioChannel, self.hexKey[2:] ) )

class MedtronicMessage( object ):
    def __init__( self, commandAction=None, session=None, payload=None ):
        self.commandAction = commandAction
        self.session = session
        self.payload = payload

    def makeMessageCcitt( self ):
        crc = crc16.crc16xmodem( self.medtronicMessage, 0xffff )
        return crc & 0xffff

    def pad( self, x, n = 16 ):
        p = n - ( len( x ) % n )
        return x + chr(p) * p

    # Encrpytion equivalent to Java's AES/CFB/NoPadding mode
    def encrypt( self, clear ):
        cipher = Crypto.Cipher.AES.new(
            key=self.session.KEY,
            mode=Crypto.Cipher.AES.MODE_CFB,
            IV=self.session.IV,
            segment_size=128
        )

        encrypted = cipher.encrypt(self.pad(clear))[0:len(clear)]
        return encrypted

    # Decryption equivalent to Java's AES/CFB/NoPadding mode
    def decrypt( self, encrypted ):
        cipher = Crypto.Cipher.AES.new(
            key=self.session.KEY,
            mode=Crypto.Cipher.AES.MODE_CFB,
            IV=self.session.IV,
            segment_size=128
        )

        decrypted = cipher.decrypt(self.pad(encrypted))[0:len(encrypted)]
        return decrypted

    def encode( self ):
        # Increment the Minimed Sequence Number
        self.session.minimedSequenceNumber += 1
        message = self.envelope + self.payload
        crc = struct.pack( '<H', crc16.crc16xmodem( message, 0xffff ) & 0xffff )
        #return message + crc
        return self.payload

class ChannelNegotiateMessage( MedtronicMessage ):
    def __init__( self, session ):
        MedtronicMessage.__init__( self, 0x03, session )
        # Size of this message is always 0x1c bytes
        # The minimedSequenceNumber is always sent as 1 for this message,
        # even though the sequence should keep incrementing as normal
        self.payload = struct.pack( '<BBBB8s', self.commandAction, 0x1c,
            1, self.session.radioChannel,
            '\x00\x00\x00\x07\x07\x00\x00\x02' )
        self.payload += struct.pack( '<Q', self.session.linkMAC )
        self.payload += struct.pack( '<Q', self.session.pumpMAC )
        crc = crc16.crc16xmodem( self.payload, 0xffff )
        self.payload += struct.pack( '<H', crc & 0xffff )

class MedtronicSendMessage( MedtronicMessage ):
    ENVELOPE_SIZE = 13

    def __init__( self, messageType, session, payload=None ):
        MedtronicMessage.__init__( self, 0x05, session )

        seqNo = 0x80
        if messageType == 0x0403:
            seqNo = 2

        sendPayload = struct.pack( '>BH', seqNo, messageType )
        if payload:
            sendPayload += payload
        crc = crc16.crc16xmodem( sendPayload, 0xffff )
        sendPayload += struct.pack( '>H', crc & 0xffff )

        print binascii.hexlify( sendPayload )
        self.payload = struct.pack( '<BBQBBB',
            self.commandAction,
            len( sendPayload ) + self.ENVELOPE_SIZE,
            self.session.pumpMAC,
            self.session.minimedSequenceNumber,
            0x10, # Unknown byte
            len( sendPayload )
        )
        self.payload += self.encrypt( sendPayload )
        crc = crc16.crc16xmodem( self.payload, 0xffff )
        self.payload += struct.pack( '<H', crc & 0xffff )

class BeginEHSMMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        payload = struct.pack( '<B', 0x00 )
        MedtronicSendMessage.__init__( self, 0x0412, session, payload )

class GetDeviceTimeMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, 0x0403, session )

class BayerBinaryMessage( object ):
    def __init__( self, messageType=None, session=None, payload=None ):
        self.payload = payload
        self.session = session
        if messageType and self.session:
            self.envelope = struct.pack( '<BB6s10sBI5sI', 0x51, 3, '000000', '\x00' * 10,
                messageType, self.session.bayerSequenceNumber, '\x00' * 5, len( self.payload ) if self.payload else 0 )
            self.envelope += struct.pack( 'B', self.makeMessageCrc() )

    def makeMessageCrc( self ):
        checksum = sum( bytearray( self.envelope )[0:32] )

        if self.payload:
            checksum += sum( bytearray( self.payload ) )

        return checksum & 0xff

    def encode( self ):
        # Increment the Bayer Sequence Number
        self.session.bayerSequenceNumber += 1
        if self.payload:
            return self.envelope + self.payload
        else:
            return self.envelope

    @classmethod
    def decode( cls, message ):
        response = cls()
        response.envelope = str( message[0:33] )
        response.payload = str( message[33:] )

        checksum = message[32]
        calcChecksum = response.makeMessageCrc()
        if( checksum != calcChecksum ):
            raise ChecksumException( 'Expected to get {0}. Got {1}'.format( calcChecksum, checksum ) )

        return response

class MedtronicMachine( object ):
    USB_BLOCKSIZE = 64
    USB_VID = 0x1a79
    USB_PID = 0x6210

    # TODO - save the last used channel to disk so we can start with that
    CHANNELS = [ 0x14, 0x11, 0x0e, 0x17, 0x1a ] # In the order that the CareLink applet requests them

    states = [ 'silent', 'device ready', 'device info', 'control mode', 'passthrough mode',
        'open connection', 'read info', 'negotiate channel', 'EHSM session', 'error' ]

    session = None

    def __init__( self ):
        self.deviceInfo = None
        self.machine = Machine( model=self, states=MedtronicMachine.states, initial='silent' )

        self.machine.add_transition( 'commsError', '*', 'error', before='closeDevice' )
        self.machine.add_transition( 'initDevice', 'silent', 'device ready', before='openDevice' )
        self.machine.add_transition( 'getDeviceInfo', 'device ready', 'device info', before='requestDeviceInfo', after='readDeviceInfo' )
        self.machine.add_transition( 'getDeviceInfo', 'device info', 'device info', before='requestDeviceInfo', after='readDeviceInfo' )
        self.machine.add_transition( 'controlMode', 'device info', 'control mode', before='enterControlMode' )
        self.machine.add_transition( 'passthroughMode', 'control mode', 'passthrough mode', before='enterPassthroughMode' )
        self.machine.add_transition( 'passthroughMode', 'control mode', 'passthrough mode', before='enterPassthroughMode' )
        self.machine.add_transition( 'openConnection', 'passthrough mode', 'open connection', before='requestOpenConnection' )
        self.machine.add_transition( 'readInfo', 'open connection', 'read info', before='requestReadInfo' )
        self.machine.add_transition( 'negotiateChannel', 'read info', 'negotiate channel', before='sendNegotiateChannel' )
        self.machine.add_transition( 'beginEHSM', 'negotiate channel', 'EHSM session', before='sendBeginEHSM' )

    def openDevice( self ):
        print "Opening device"
        self.device = hid.device()
        self.device.open( self.USB_VID, self.USB_PID )

        print "Manufacturer: %s" % self.device.get_manufacturer_string()
        print "Product: %s" % self.device.get_product_string()
        print "Serial No: %s" % self.device.get_serial_number_string()

    def closeDevice( self ):
        print "Closing device"
        self.device.close()

    def readMessage( self ):
        payload = bytearray()
        while True:
            data = self.device.read( self.USB_BLOCKSIZE, timeout_ms = 5000 )
            if data:
                if( str( bytearray( data[0:3] ) ) != 'ABC' ):
                    raise RuntimeError( 'Recieved invalid USB packet')
                payload.extend( data[4:data[3] + 4] )
                # TODO - how to deal with messages that finish on the boundary?
                if data[3] != self.USB_BLOCKSIZE - 4:
                    break
            else:
                raise TimeoutException( 'Timeout waiting for message' )

        print "READ: " + binascii.hexlify( payload ) # Debugging
        return payload

    def sendMessage( self, hexMessage ):
        # Split the message into 60 byte chunks
        for packet in [ hexMessage[ i: i+60 ] for i in range( 0, len( hexMessage ), 60 ) ]:
            message = struct.pack( '>3sB', 'ABC', len( packet ) ) + packet
            self.device.write( bytearray( message ) )
            print "SEND: " + binascii.hexlify( message ) # Debugging

    def requestDeviceInfo( self ):
        print "Request Device Info"
        self.sendMessage( struct.pack( '>B', 0x58 ) )

    @property
    def deviceSerial( self ):
        if not self.deviceInfo:
            return None
        else:
            return self.deviceInfo[0][4][3][1]

    def readDeviceInfo( self ):
        print "Read Device Info"

        try:
            msg = self.readMessage()

            if not astm.codec.is_chunked_message( msg ):
                raise RuntimeError( 'Expected to get an ASTM message, but got {0} instead'.format( binascii.hexlify( msg ) ) )

            self.deviceInfo = astm.codec.decode( str( msg ) )
            self.checkControlMessage( curses.ascii.ENQ )

        except TimeoutException as e:
            self.sendMessage( struct.pack( '>B', curses.ascii.EOT ) )
            self.checkControlMessage( curses.ascii.ENQ )
            self.getDeviceInfo()

    def checkControlMessage( self, controlChar ):
        msg = self.readMessage()
        if not ( len( msg ) == 1 and msg[0] == controlChar ):
            raise RuntimeError( 'Expected to get an {0} control character'.format( hex( controlChar ) ) )

    def enterControlMode( self ):
        # TODO - should this be a mini FSM?
        self.sendMessage( struct.pack( '>B', curses.ascii.NAK ) )
        self.checkControlMessage( curses.ascii.EOT )
        self.sendMessage( struct.pack( '>B', curses.ascii.ENQ ) )
        self.checkControlMessage( curses.ascii.ACK )

    def enterPassthroughMode( self ):
        # TODO - should this be a mini FSM?
        self.sendMessage( struct.pack( '>2s', 'W|' ) )
        self.checkControlMessage( curses.ascii.ACK )
        self.sendMessage( struct.pack( '>2s', 'Q|' ) )
        self.checkControlMessage( curses.ascii.ACK )
        self.sendMessage( struct.pack( '>2s', '1|' ) )
        self.checkControlMessage( curses.ascii.ACK )

    def requestOpenConnection( self ):
        print "Request Open Connection"

        # FIXME - we'd pass in the key here normally. It's currently defaulting to Lennart's key
        self.session = MedtronicSession()

        mtMessage = binascii.unhexlify( self.session.HMAC )
        bayerMessage = BayerBinaryMessage( 0x10, self.session, mtMessage )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage()

    def requestReadInfo( self ):
        print "Request Read Info"
        bayerMessage = BayerBinaryMessage( 0x14, self.session )
        self.sendMessage( bayerMessage.encode() )
        # TODO - make a responseReadInfo that stores serials into this the session. They're hardcoded ATM
        self.readMessage()

    def sendNegotiateChannel( self ):
        print "Send Negotiate Channel"

        for self.session.radioChannel in self.CHANNELS:
            print "Negotiating on channel {0}".format( self.session.radioChannel )

            mtMessage = ChannelNegotiateMessage( self.session )

            bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
            self.sendMessage( bayerMessage.encode() )
            self.readMessage() # Read the 0x81
            response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
            if len( response.payload ) > 13:
                # Check that the channel ID matches
                responseChannel = struct.unpack( 'B', response.payload[43] )[0]
                if self.session.radioChannel == responseChannel:
                    break
                else:
                    raise UnexpectedMessageException( "Expected to get a message for channel {0}. Got {1}".format( self.session.radioChannel, responseChannel ) )
            else:
                self.session.radioChannel = None

        if not self.session.radioChannel:
            raise NegotiationException( 'Could not negotiate a comms channel with the pump. Are you near to the pump?' )

    def sendBeginEHSM( self ):
        print "Begin Extended High Speed Mode Session"
        mtMessage = BeginEHSMMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # The Begin EHSM only has an 0x81 response.

    def getDeviceTime( self ):
        print "Get Device Time"
        if self.state != 'EHSM session':
            raise UnexpectedStateException( 'Device needs to be in EHSM to request device time' )
        mtMessage = GetDeviceTimeMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # Read the 0x81
        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        print binascii.hexlify( response.payload )

mt = MedtronicMachine()
mt.initDevice()
mt.getDeviceInfo()
print mt.deviceSerial
mt.controlMode()
mt.passthroughMode()
mt.openConnection()
mt.readInfo()
mt.negotiateChannel()
mt.beginEHSM()
mt.getDeviceTime()
