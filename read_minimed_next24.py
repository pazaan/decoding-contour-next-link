#!/usr/bin/env python

import hid # pip install hidapi - Platform independant
import astm # pip install astm
from transitions import Machine # pip install transitions
import struct
import binascii
import sys
import time
import datetime
from dateutil import tz
import crc16 # pip install crc16
import Crypto.Cipher.AES # pip install PyCrypto
import sqlite3

ascii= {
    'ACK' : 0x06,
    'CR' : 0x0D,
    'ENQ' : 0x05,
    'EOT' : 0x04,
    'ETB' : 0x17,
    'ETX' : 0x03,
    'LF' : 0x0A,
    'NAK' : 0x15,
    'STX' : 0x02
}

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

class Config( object ):
    def __init__( self, stickSerial ):
        self.conn = sqlite3.connect( 'read_minimed.db' )
        self.c = self.conn.cursor()
        self.c.execute( '''CREATE TABLE IF NOT EXISTS
            config ( stick_serial TEXT PRIMARY KEY, hmac TEXT, key TEXT, last_radio_channel INTEGER )''' )
        self.c.execute( "INSERT OR IGNORE INTO config VALUES ( ?, ?, ?, ? )", ( stickSerial, '', '', 0x14 ) )
        self.conn.commit()

        self.loadConfig( stickSerial )

    def loadConfig( self, stickSerial ):
        self.c.execute( 'SELECT * FROM config WHERE stick_serial = ?', ( stickSerial, ) )
        self.data = self.c.fetchone()

    @property
    def stickSerial( self ):
        return self.data[0]

    @property
    def lastRadioChannel( self ):
        return self.data[3]

    @lastRadioChannel.setter
    def lastRadioChannel( self, value ):
        self.c.execute( "UPDATE config SET last_radio_channel = ? WHERE stick_serial = ?", ( value, self.stickSerial ) )
        self.conn.commit()
        self.loadConfig( self.stickSerial )

    @property
    def hmac( self ):
        return self.data[1]

    @hmac.setter
    def hmac( self, value ):
        self.c.execute( "UPDATE config SET hmac = ? WHERE stick_serial = ?", ( value, self.stickSerial ) )
        self.conn.commit()
        self.loadConfig( self.stickSerial )

    @property
    def key( self ):
        return self.data[2]

    @key.setter
    def key( self, value ):
        self.c.execute( "UPDATE config SET key = ? WHERE stick_serial = ?", ( value, self.stickSerial ) )
        self.conn.commit()
        self.loadConfig( self.stickSerial )

class DateTimeHelper( object ):
    @staticmethod
    def decodeDateTime( pumpDateTime ):
        rtc = ( pumpDateTime >> 32 ) & 0xffffffff
        offset = ( pumpDateTime & 0xffffffff ) - 0x100000000

        # Base time is midnight 1st Jan 2000 (UTC)
        baseTime = 946684800;

        # The time from the pump represents epochTime in UTC, but we treat it as if it were in our own timezone
        # We do this, because the pump does not have a concept of timezone
        # For example, if baseTime + rtc + offset was 1463137668, this would be
        # Fri, 13 May 2016 21:07:48 UTC.
        # However, the time the pump *means* is Fri, 13 May 2016 21:07:48 in our own timezone
        offsetFromUTC = int(datetime.datetime.utcnow().strftime('%s')) - int(datetime.datetime.now().strftime('%s'))
        epochTime = baseTime + rtc + offset + offsetFromUTC

        # Return a non-naive datetime in the local timezone
        # (so that we can convert to UTC for Nightscout later)
        localTz = tz.tzlocal()
        return datetime.datetime.fromtimestamp( epochTime, localTz )

class MedtronicSession( object ):
    radioChannel = None
    bayerSequenceNumber = 1
    minimedSequenceNumber = 1

    @property
    def HMAC( self ):
        if self.config.hmac == "":
            raise Exception( "HMAC not found in config database. Run get_hmac_and_key.py to get populate HMAC and key." )
        return self.config.hmac

    @property
    def hexKey( self ):
        if self.config.key == "":
            raise Exception( "Key not found in config database. Run get_hmac_and_key.py to get populate HMAC and key." )
        return self.config.key

    @property
    def stickSerial( self ):
        return self._stickSerial

    @stickSerial.setter
    def stickSerial( self, value ):
        self._stickSerial = value
        self.config = Config( self.stickSerial )

    @property
    def linkMAC( self ):
        return self._linkMAC

    @linkMAC.setter
    def linkMAC( self, value ):
        self._linkMAC = value

    @property
    def pumpMAC( self ):
        return self._pumpMAC

    @pumpMAC.setter
    def pumpMAC( self, value ):
        self._pumpMAC = value

    @property
    def linkSerial( self ):
        return self.linkMAC & 0xffffff

    @property
    def pumpSerial( self ):
        return self.pumpMAC & 0xffffff

    @property
    def KEY( self ):
        return binascii.unhexlify( self.hexKey )

    @property
    def IV( self ):
        return binascii.unhexlify( "{0:02x}{1}".format( self.radioChannel, self.hexKey[2:] ) )

class MedtronicMessage( object ):
    ENVELOPE_SIZE = 2

    def __init__( self, commandAction=None, session=None, payload=None ):
        self.commandAction = commandAction
        self.session = session
        if payload:
            self.setPayload( payload )

    def setPayload( self, payload ):
        self.payload = payload
        self.envelope = struct.pack( '<BB', self.commandAction,
            len( self.payload ) + self.ENVELOPE_SIZE )

    @classmethod
    def calculateCcitt( self, data ):
        crc = crc16.crc16xmodem( data, 0xffff )
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
        return message + crc

    @classmethod
    def decode( cls, message, session ):
        response = cls()
        response.session = session
        response.envelope = str( message[0:2] )
        response.payload = str( message[2:-2] )

        checksum = struct.unpack( '<H', str( message[-2:] ) )[0]
        calcChecksum = MedtronicMessage.calculateCcitt( response.envelope + response.payload )
        if( checksum != calcChecksum ):
            raise ChecksumException( 'Expected to get {0}. Got {1}'.format( calcChecksum, checksum ) )

        return response

class ChannelNegotiateMessage( MedtronicMessage ):
    def __init__( self, session ):
        MedtronicMessage.__init__( self, 0x03, session )

        # The minimedSequenceNumber is always sent as 1 for this message,
        # even though the sequence should keep incrementing as normal
        payload = struct.pack( '<BB8s', 1, session.radioChannel,
            '\x00\x00\x00\x07\x07\x00\x00\x02' )
        payload += struct.pack( '<Q', session.linkMAC )
        payload += struct.pack( '<Q', session.pumpMAC )

        self.setPayload( payload )

class MedtronicSendMessage( MedtronicMessage ):
    def __init__( self, messageType, session, payload=None ):
        MedtronicMessage.__init__( self, 0x05, session )

        # FIXME - make this not be hard coded
        seqNo = 0x80
        if messageType == 0x0403:
            seqNo = 2
        elif messageType == 0x0112:
            seqNo = 3
        elif messageType == 0x0115:
            seqNo = 4
        elif messageType == 0x0114:
            seqNo = 5
        elif messageType == 0x0200:
            seqNo = 6
        elif messageType == 0x0100:
            seqNo = 4

        encryptedPayload = struct.pack( '>BH', seqNo, messageType )
        if payload:
            encryptedPayload += payload
        crc = crc16.crc16xmodem( encryptedPayload, 0xffff )
        encryptedPayload += struct.pack( '>H', crc & 0xffff )

        mmPayload = struct.pack( '<QBBB',
            self.session.pumpMAC,
            self.session.minimedSequenceNumber,
            0x10, # Unknown byte
            len( encryptedPayload )
        )
        mmPayload += self.encrypt( encryptedPayload )

        self.setPayload( mmPayload )

class MedtronicReceiveMessage( MedtronicMessage ):
    @classmethod
    def decode( cls, message, session ):
        response = MedtronicMessage.decode( message, session )
        # TODO - check validity of the envelope
        response.responseEnvelope = str( response.payload[0:22] )
        decryptedResponsePayload = response.decrypt( str( response.payload[22:] ) )

        response.responsePayload = decryptedResponsePayload[0:-2]

        checksum = struct.unpack( '>H', str( decryptedResponsePayload[-2:] ) )[0]
        calcChecksum = MedtronicMessage.calculateCcitt( response.responsePayload )
        if( checksum != calcChecksum ):
            raise ChecksumException( 'Expected to get {0}. Got {1}'.format( calcChecksum, checksum ) )

        return response

class ReadInfoResponseMessage( object ):
    @classmethod
    def decode( cls, message ):
        response = cls()
        response.responsePayload = message
        return response

    @property
    def linkMAC( self ):
        return struct.unpack( '>Q', self.responsePayload[0:8] )[0]

    @property
    def pumpMAC( self ):
        return struct.unpack( '>Q', self.responsePayload[8:16] )[0]

class PumpTimeResponseMessage( MedtronicReceiveMessage ):
    @classmethod
    def decode( cls, message, session ):
        response = MedtronicReceiveMessage.decode( message, session )
        messageType = struct.unpack( '>H', response.responsePayload[1:3] )[0]
        if messageType != 0x407:
            raise UnexpectedMessageException( "Expected to get a Time Response message '{0}'. Got {1}.".format( 0x407, messageType ) )

        # Since we only add behaviour, we can cast this class to ourselves
        response.__class__ = PumpTimeResponseMessage
        return response

    @property
    def timeSet( self ):
        if struct.unpack( 'B', self.responsePayload[3:3] )[0] == 0:
            return false
        else:
            return true

    @property
    def datetime( self ):
        dateTimeData = struct.unpack( '>Q', self.responsePayload[4:] )[0]
        return DateTimeHelper.decodeDateTime( dateTimeData )

class PumpStatusResponseMessage( MedtronicReceiveMessage ):
    MMOL = 1
    MGDL = 2

    @classmethod
    def decode( cls, message, session ):
        response = MedtronicReceiveMessage.decode( message, session )
        messageType = struct.unpack( '>H', response.responsePayload[1:3] )[0]
        if messageType != 0x13c:
            raise UnexpectedMessageException( "Expected to get a Status Response message '{0}'. Got {1}.".format( 0x13c, messageType ) )

        # Since we only add behaviour, we can cast this class to ourselves
        response.__class__ = PumpStatusResponseMessage
        return response

    @property
    def currentBasalRate( self ):
        return float( struct.unpack( '>I', self.responsePayload[0x1b:0x1f] )[0] ) / 10000

    @property
    def tempBasalRate( self ):
        return float( struct.unpack( '>H', self.responsePayload[0x21:0x23] )[0] )

    @property
    def tempBasalPercentage( self ):
        return int( struct.unpack( '>B', self.responsePayload[0x23:0x24] )[0] )

    @property
    def tempBasalMinutesRemaining( self ):
        return int( struct.unpack( '>H', self.responsePayload[0x24:0x26] )[0] )

    @property
    def batteryLevelPercentage( self ):
        return int( struct.unpack( '>B', self.responsePayload[0x2a:0x2b] )[0] )

    @property
    def insulinUnitsRemaining( self ):
        return int( struct.unpack( '>I', self.responsePayload[0x2b:0x2f] )[0] ) / 10000

    @property
    def activeInsulin( self ):
        return float( struct.unpack( '>H', self.responsePayload[51:53] )[0] ) / 10000

    @property
    def sensorBGL( self ):
        return int( struct.unpack( '>H', self.responsePayload[53:55] )[0] )

    @property
    def trendArrow( self ):
        status = int( struct.unpack( '>B', self.responsePayload[0x40:0x41] )[0] )
        if status == 0x60:
            return "No arrows"
        elif status == 0xc0:
            return "3 arrows up"
        elif status == 0xa0:
            return "2 arrows up"
        elif status == 0x80:
            return "1 arrow up"
        elif status == 0x40:
            return "1 arrow down"
        elif status == 0x20:
            return "2 arrows down"
        elif status == 0x00:
            return "3 arrows down"
        else:
            return "Unknown trend"

    @property
    def sensorBGLTimestamp( self ):
        dateTimeData = struct.unpack( '>Q', self.responsePayload[55:63] )[0]
        return DateTimeHelper.decodeDateTime( dateTimeData )

    @property
    def recentBolusWizard( self ):
        if struct.unpack( 'B', self.responsePayload[72:72] )[0] == 0:
            return false
        else:
            return true

    @property
    def bolusWizardBGL( self ):
        return struct.unpack( '>H', self.responsePayload[73:75] )[0]

class BeginEHSMMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        payload = struct.pack( '<B', 0x00 )
        MedtronicSendMessage.__init__( self, 0x0412, session, payload )

class PumpTimeRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, 0x0403, session )

class PumpStatusRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, 0x0112, session )

class DeviceCharacteristicsRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, 0x0200, session )

class PumpTempBasalRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, 0x0115, session )

class PumpBolusesRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, 0x0114, session )

class PumpRemoteBolusRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        payload = struct.pack( '>H', 5000 )
        MedtronicSendMessage.__init__( self, 0x0100, session, payload )

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

    CHANNELS = [ 0x14, 0x11, 0x0e, 0x17, 0x1a ] # In the order that the CareLink applet requests them

    states = [ 'silent', 'device ready', 'device info', 'control mode', 'passthrough mode',
        'open connection', 'read info', 'negotiate channel', 'EHSM session', 'error' ]

    session = None

    def __init__( self ):
        self.session = MedtronicSession()
        self.device = None

        self.deviceInfo = None
        self.machine = Machine( model=self, states=MedtronicMachine.states, initial='silent' )

        self.machine.add_transition( 'commsError', '*', 'error', before='closeDevice' )
        self.machine.add_transition( 'initDevice', 'silent', 'device ready', before='openDevice' )
        self.machine.add_transition( 'getDeviceInfo', 'device ready', 'device info', before='requestDeviceInfo', after='readDeviceInfo' )
        self.machine.add_transition( 'getDeviceInfo', 'device info', 'device info', before='requestDeviceInfo', after='readDeviceInfo' )
        self.machine.add_transition( 'controlMode', 'device info', 'control mode', before='enterControlMode' )
        self.machine.add_transition( 'passthroughMode', 'control mode', 'passthrough mode', before='enterPassthroughMode' )
        self.machine.add_transition( 'openConnection', 'passthrough mode', 'open connection', before='requestOpenConnection' )
        self.machine.add_transition( 'readInfo', 'open connection', 'read info', before='requestReadInfo' )
        self.machine.add_transition( 'negotiateChannel', 'read info', 'negotiate channel', before='doNegotiateChannel' )
        self.machine.add_transition( 'beginEHSM', 'negotiate channel', 'EHSM session', before='sendBeginEHSM' )

    def openDevice( self ):
        print "# Opening device"
        self.device = hid.device()
        self.device.open( self.USB_VID, self.USB_PID )

        print "Manufacturer: %s" % self.device.get_manufacturer_string()
        print "Product: %s" % self.device.get_product_string()
        print "Serial No: %s" % self.device.get_serial_number_string()

    def closeDevice( self ):
        print "# Closing device"
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

        #print "READ: " + binascii.hexlify( payload ) # Debugging
        return payload

    def sendMessage( self, payload ):
        # Split the message into 60 byte chunks
        for packet in [ payload[ i: i+60 ] for i in range( 0, len( payload ), 60 ) ]:
            message = struct.pack( '>3sB', 'ABC', len( packet ) ) + packet
            self.device.write( bytearray( message ) )
            #print "SEND: " + binascii.hexlify( message ) # Debugging

    def requestDeviceInfo( self ):
        print "# Request Device Info"
        self.sendMessage( struct.pack( '>B', 0x58 ) )

    @property
    def deviceSerial( self ):
        if not self.deviceInfo:
            return None
        else:
            return self.deviceInfo[0][4][3][1]

    def readDeviceInfo( self ):
        print "# Read Device Info"

        try:
            msg = self.readMessage()

            if not astm.codec.is_chunked_message( msg ):
                raise RuntimeError( 'Expected to get an ASTM message, but got {0} instead'.format( binascii.hexlify( msg ) ) )

            self.deviceInfo = astm.codec.decode( str( msg ) )
            self.session.stickSerial = self.deviceSerial
            self.checkControlMessage( ascii['ENQ'] )

        except TimeoutException as e:
            self.sendMessage( struct.pack( '>B', ascii['EOT'] ) )
            self.checkControlMessage( ascii['ENQ'] )
            self.getDeviceInfo()

    def checkControlMessage( self, controlChar ):
        msg = self.readMessage()
        if not ( len( msg ) == 1 and msg[0] == controlChar ):
            raise RuntimeError( 'Expected to get an {0} control character'.format( hex( controlChar ) ) )

    def enterControlMode( self ):
        # TODO - should this be a mini FSM?
        self.sendMessage( struct.pack( '>B', ascii['NAK'] ) )
        self.checkControlMessage( ascii['EOT'] )
        self.sendMessage( struct.pack( '>B', ascii['ENQ'] ) )
        self.checkControlMessage( ascii['ACK'] )

    def enterPassthroughMode( self ):
        # TODO - should this be a mini FSM?
        self.sendMessage( struct.pack( '>2s', 'W|' ) )
        self.checkControlMessage( ascii['ACK'] )
        self.sendMessage( struct.pack( '>2s', 'Q|' ) )
        self.checkControlMessage( ascii['ACK'] )
        self.sendMessage( struct.pack( '>2s', '1|' ) )
        self.checkControlMessage( ascii['ACK'] )

    def requestOpenConnection( self ):
        print "# Request Open Connection"

        mtMessage = binascii.unhexlify( self.session.HMAC )
        bayerMessage = BayerBinaryMessage( 0x10, self.session, mtMessage )
        self.sendMessage( bayerMessage.encode() )
        message = self.readMessage()

    def requestReadInfo( self ):
        print "# Request Read Info"
        bayerMessage = BayerBinaryMessage( 0x14, self.session )
        self.sendMessage( bayerMessage.encode() )
        response = BayerBinaryMessage.decode( self.readMessage() ) # The response is a 0x14 as well
        info = ReadInfoResponseMessage.decode( response.payload )
        self.session.linkMAC = info.linkMAC
        self.session.pumpMAC = info.pumpMAC

    def doNegotiateChannel( self ):
        print "# Negotiate pump comms channel"

        # Scan the last successfully connected channel first, since this could save us negotiating time
        for self.session.radioChannel in [ self.session.config.lastRadioChannel ] + self.CHANNELS:
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
        else:
            self.session.config.lastRadioChannel = self.session.radioChannel

    def sendBeginEHSM( self ):
        print "# Begin Extended High Speed Mode Session"
        mtMessage = BeginEHSMMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # The Begin EHSM only has an 0x81 response.

    def getPumpTime( self ):
        print "# Get Pump Time"
        if self.state != 'EHSM session':
            raise UnexpectedStateException( 'Link needs to be in EHSM to request device time' )
        mtMessage = PumpTimeRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # Read the 0x81
        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        return PumpTimeResponseMessage.decode( response.payload, self.session ).datetime

    def getPumpStatus( self ):
        print "# Get Pump Status"
        if self.state != 'EHSM session':
            raise UnexpectedStateException( 'Link needs to be in EHSM to request device time' )
        mtMessage = PumpStatusRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # Read the 0x81
        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        return PumpStatusResponseMessage.decode( response.payload, self.session )

    def getTempBasalStatus( self ):
        print "# Get Temp Basal Status"
        if self.state != 'EHSM session':
            raise UnexpectedStateException( 'Link needs to be in EHSM to request device time' )
        mtMessage = PumpTempBasalRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # Read the 0x81
        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def getBolusesStatus( self ):
        print "# Get Boluses Status"
        if self.state != 'EHSM session':
            raise UnexpectedStateException( 'Link needs to be in EHSM to request device time' )
        mtMessage = PumpBolusesRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # Read the 0x81
        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def doRemoteBasal( self ):
        print "# Execute Remote Bolus"
        if self.state != 'EHSM session':
            raise UnexpectedStateException( 'Link needs to be in EHSM to request device time' )
        mtMessage = PumpRemoteBolusRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage() # Read the 0x81
        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        return MedtronicReceiveMessage.decode( response.payload, self.session )

if __name__ == '__main__':
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
    print mt.getPumpTime().strftime( "Pump time is: %c" )
    status = mt.getPumpStatus()
    print binascii.hexlify( status.responsePayload )
    print "Active Insulin: {0:.3f}U".format( status.activeInsulin )
    print "Sensor BGL: {0} mg/dL ({1:.1f} mmol/L) at {2}".format( status.sensorBGL,
        status.sensorBGL / 18.016,
        status.sensorBGLTimestamp.strftime( "%c" ) )
    print "BGL trend: {0}".format( status.trendArrow )
    print "Current basal rate: {0:.3f}U".format( status.currentBasalRate )
    print "Units remaining: {0:.3f}U".format( status.insulinUnitsRemaining )
    print "Battery remaining: {0}%".format( status.batteryLevelPercentage )
    #print binascii.hexlify( mt.getTempBasalStatus().responsePayload )
    #print binascii.hexlify( mt.getBolusesStatus().responsePayload )
    #print binascii.hexlify( mt.doRemoteBasal().responsePayload )
