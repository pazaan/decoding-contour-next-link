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

class TimeoutException( Exception ):
    pass

class ChecksumException( Exception ):
    pass

class UnexpectedMessageException( Exception ):
    pass

class NegotiationException( Exception ):
    pass

class MedtronicMessage( object ):
    def __init__( self, commandAction=None ):
        self.commandAction = commandAction

    def makeMessageCcitt( self ):
        crc = crc16.crc16xmodem( self.medtronicMessage, 0xffff )
        return crc & 0xffff

    def pad( self, x, n = 16 ):
        p = n - ( len( x ) % n )
        return x + chr(p) * p

    def getIV( self, key, radioChannel ):
        return binascii.unhexlify( "{0:02x}{1}".format( radioChannel, key[2:] ) )

    # Encrpytion equivalent to Java's AES/CFB/NoPadding mode
    def encrypt( self, clear, key, radioChannel ):
        cipher = Crypto.Cipher.AES.new(
            key=key,
            mode=Crypto.Cipher.AES.MODE_CFB,
            IV=self.getIV( key, radioChannel ),
            segment_size=128
        )

        encrypted = cipher.encrypt(self.pad(clear))[0:len(clear)]
        return encrypted

    # Decryption equivalent to Java's AES/CFB/NoPadding mode
    def decrypt( self, encrypted, key, radioChannel ):
        cipher = Crypto.Cipher.AES.new(
            key=key,
            mode=Crypto.Cipher.AES.MODE_CFB,
            IV=self.getIV( key, radioChannel ),
            segment_size=128
        )

        decrypted = cipher.decrypt(self.pad(encrypted))[0:len(encrypted)]
        return decrypted

    def encode( self ):
        return self.payload

class ChannelNegotiateMessage( MedtronicMessage ):
    def __init__( self, sequenceNumber, channel, linkMAC, pumpMAC ):
        MedtronicMessage.__init__( self, 0x03 )
        self.payload = struct.pack( '<BBBB8s', self.commandAction, 0x1c, sequenceNumber, channel,
            '\x00\x00\x00\x07\x07\x00\x00\x02' )
        self.payload += struct.pack( '<Q', linkMAC )
        self.payload += struct.pack( '<Q', pumpMAC )
        crc = crc16.crc16xmodem( self.payload, 0xffff )
        self.payload += struct.pack( '<H', crc & 0xffff )

class BayerBinaryMessage( object ):
    def __init__( self, messageType=None, sequenceNumber=None, payload=None ):
        self.payload = payload
        if messageType and sequenceNumber:
            self.envelope = struct.pack( '<BB6s10sBI5sI', 0x51, 3, '000000', '\x00' * 10,
                messageType, sequenceNumber, '\x00' * 5, len( self.payload ) if self.payload else 0 )
            self.envelope += struct.pack( 'B', self.makeMessageCrc() )

    def makeMessageCrc( self ):
        checksum = 0
        checksum += sum( bytearray( self.envelope )[0:32] )

        if self.payload:
            checksum += sum( bytearray( self.payload ) )

        return checksum & 0xff

    def encode( self ):
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

    # FIXME - hardcoded for Lennart's pump
    HMAC = 'e28fe4e5cf3c1eb6d6a2ec5a093093d4f397237dc60b3f2c1ef64f31e32077c4'
    linkMAC = 1055866 + 0x0023F70682000000
    pumpMAC = 1057941 + 0x0023F745EE000000
    radioChannel = None

    CHANNELS = [ 0x14, 0x11, 0x0e, 0x17, 0x1a ] # In the order that the CareLink applet requests them

    states = [ 'silent', 'device ready', 'device info', 'control mode', 'passthrough mode',
        'open connection', 'read info', 'negotiate channel', 'EHSM session', 'error' ]

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
        sn = 1 # sequence number
        mtMessage = binascii.unhexlify( self.HMAC )
        bayerMessage = BayerBinaryMessage( 0x10, sn, mtMessage )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage()

    def requestReadInfo( self ):
        print "Request Read Info"
        sn = 2 # sequence number
        bayerMessage = BayerBinaryMessage( 0x14, sn )
        self.sendMessage( bayerMessage.encode() )
        # TODO - make a responseReadInfo that stores serials into this object. Hardcoded for now
        self.readMessage()

    def sendNegotiateChannel( self ):
        print "Send Negotiate Channel"
        sn = 3 # sequence number
        mtSn = 1 # Medtronic sequence number

        for channel in self.CHANNELS:
            print "Negotiating on channel {0}".format( channel )

            mtMessage = ChannelNegotiateMessage( mtSn, channel, self.linkMAC, self.pumpMAC )

            bayerMessage = BayerBinaryMessage( 0x12, sn, mtMessage.encode() )
            self.sendMessage( bayerMessage.encode() )
            self.readMessage() # Read the 0x81
            response = BayerBinaryMessage().decode( self.readMessage() ) # Read the 0x80
            print binascii.hexlify( response.payload )
            if len( response.payload ) > 13:
                # Check that the channel ID matches
                self.radioChannel = struct.unpack( 'B', response.payload[43] )[0]
                if self.radioChannel == channel:
                    break
                else:
                    raise UnexpectedMessageException( "Expected to get a message for channel {0}. Got {1}".format( channel, self.radioChannel ) )

        if not self.radioChannel:
            raise NegotiationException( 'Could not negotiate a comms channel with the pump. Are you near to the pump?' )

    def sendBeginEHSM( self ):
        print "Begin Extended High Speed Mode Session"

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

print mt.state
