#!/usr/bin/env python

import logging
# logging.basicConfig has to be before astm import, otherwise logs don't appear
logging.basicConfig(format='%(asctime)s %(levelname)s [%(name)s] %(message)s', level=logging.WARNING)
# a nasty workaround on missing hidapi.dll on my windows (allows testing from saved files, but not download of pump)
try:
    import hid # pip install hidapi - Platform independant
except WindowsError:
    pass
import astm # pip install astm
import struct
import binascii
import datetime
import crc16 # pip install crc16
import Crypto.Cipher.AES # pip install PyCrypto
import sqlite3
import hashlib
import re
import pickle # needed for local history export
import lzo # pip install python-lzo
from .pump_history_parser import NGPHistoryEvent, BloodGlucoseReadingEvent
from .helpers import DateTimeHelper

logger = logging.getLogger(__name__)

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

def ord_hack(char_or_byte):
    return char_or_byte if isinstance(char_or_byte, int) else ord(char_or_byte)

class COM_D_COMMAND:
    HIGH_SPEED_MODE_COMMAND = 0x0412
    TIME_REQUEST = 0x0403
    TIME_RESPONSE = 0x0407
    READ_PUMP_STATUS_REQUEST = 0x0112
    READ_PUMP_STATUS_RESPONSE = 0x013C
    READ_BASAL_PATTERN_REQUEST = 0x0116
    READ_BASAL_PATTERN_RESPONSE = 0x0123
    READ_BOLUS_WIZARD_CARB_RATIOS_REQUEST = 0x012B
    READ_BOLUS_WIZARD_CARB_RATIOS_RESPONSE = 0x012C
    READ_BOLUS_WIZARD_SENSITIVITY_FACTORS_REQUEST = 0x012E
    READ_BOLUS_WIZARD_SENSITIVITY_FACTORS_RESPONSE = 0x012F
    READ_BOLUS_WIZARD_BG_TARGETS_REQUEST = 0x0131
    READ_BOLUS_WIZARD_BG_TARGETS_RESPONSE = 0x0132
    DEVICE_STRING_REQUEST = 0x013A
    DEVICE_STRING_RESPONSE = 0x013B
    DEVICE_CHARACTERISTICS_REQUEST = 0x0200
    DEVICE_CHARACTERISTICS_RESPONSE = 0x0201
    READ_HISTORY_REQUEST = 0x0304
    READ_HISTORY_RESPONSE = 0x0305
    END_HISTORY_TRANSMISSION = 0x030A
    READ_HISTORY_INFO_REQUEST = 0x030C
    READ_HISTORY_INFO_RESPONSE = 0x030D
    UNMERGED_HISTORY_RESPONSE = 0x030E
    INITIATE_MULTIPACKET_TRANSFER = 0xFF00
    MULTIPACKET_SEGMENT_TRANSMISSION = 0xFF01
    MULTIPACKET_RESEND_PACKETS = 0xFF02
    ACK_MULTIPACKET_COMMAND = 0x00FE # TODO ACK_COMMAND
    NAK_COMMAND = 0x00FF
    BOLUSES_REQUEST = 0x0114
    REMOTE_BOLUS_REQUEST = 0x0100
    REQUEST_0x0124 = 0x0124
    REQUEST_0x0405 = 0x0405
    TEMP_BASAL_REQUEST = 0x0115
    SUSPEND_RESUME_REQUEST = 0x0107
    NGP_PARAMETER_REQUEST = 0x0138

class HISTORY_DATA_TYPE:
    PUMP_DATA = 0x02
    SENSOR_DATA = 0x03

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

class InvalidMessageError( Exception ):
    pass

class ChecksumError( Exception ):
    pass

class DataIncompleteError( Exception ):
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

class MedtronicSession( object ):
    radioChannel = None
    bayerSequenceNumber = 1
    minimedSequenceNumber = 1
    sendSequenceNumber = 0

    @property
    def HMAC( self ):
        serial = bytearray( re.sub( r"\d+-", "", self.stickSerial ), 'ascii' ) 
        paddingKey = b"A4BD6CED9A42602564F413123"
        digest = hashlib.sha256(serial + paddingKey).hexdigest()
        return "".join(reversed([digest[i:i+2] for i in range(0, len(digest), 2)]))

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
        self.radioChannel = self.config.lastRadioChannel

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
        return self._key

    @KEY.setter
    def KEY( self, value ):
        self._key = value

    @property
    def IV( self ):
        tmp = bytearray()
        tmp.append(self.radioChannel)
        tmp += self.KEY[1:]        
        return bytes(tmp)

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
        crc = crc16.crc16xmodem( bytes(data), 0xffff )
        return crc & 0xffff

    def pad( self, x, n = 16 ):
        p = n - ( len( x ) % n )
        return x + bytes(bytearray(p))#chr(p) * p

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
        response.envelope = message[0:2]
        response.payload = message[2:-2]
        response.originalMessage = message;

        checksum = struct.unpack( '<H', message[-2:] )[0]
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
            b'\x00\x00\x00\x07\x07\x00\x00\x02' )
        payload += struct.pack( '<Q', session.linkMAC )
        payload += struct.pack( '<Q', session.pumpMAC )

        self.setPayload( payload )

class MedtronicSendMessage( MedtronicMessage ):
    def __init__( self, messageType, session, payload=None ):
        MedtronicMessage.__init__( self, 0x05, session )

        # FIXME - make this not be hard coded
        if messageType == COM_D_COMMAND.HIGH_SPEED_MODE_COMMAND:
            seqNo = self.session.sendSequenceNumber | 0x80
        else:
            seqNo = self.session.sendSequenceNumber

        encryptedPayload = struct.pack( '>BH', seqNo, messageType )
        if payload:
            encryptedPayload += payload
        crc = crc16.crc16xmodem( encryptedPayload, 0xffff )
        encryptedPayload += struct.pack( '>H', crc & 0xffff )
        # logger.debug("### PAYLOAD")
        # logger.debug(binascii.hexlify( encryptedPayload ))
        
        mmPayload = struct.pack( '<QBBB',
            self.session.pumpMAC,
            self.session.minimedSequenceNumber,
            0x11, # Mode flags
            len( encryptedPayload )
        )        
        mmPayload += self.encrypt( encryptedPayload )

        self.setPayload( mmPayload )
        self.session.sendSequenceNumber += 1

class MedtronicReceiveMessage( MedtronicMessage ):
    @classmethod
    def decode( cls, message, session ):
        response = MedtronicMessage.decode( message, session )
       
        # TODO - check validity of the envelope
        response.responseEnvelope = response.payload[0:22] 
        decryptedResponsePayload = response.decrypt( bytes(response.payload[22:]) )

        response.responsePayload = decryptedResponsePayload[0:-2]

        # logger.debug("### DECRYPTED PAYLOAD:")
        # logger.debug(binascii.hexlify( response.responsePayload ))

        if len( response.responsePayload ) > 2:
            checksum = struct.unpack( '>H', decryptedResponsePayload[-2:])[0]
            calcChecksum = MedtronicMessage.calculateCcitt( response.responsePayload )
            if( checksum != calcChecksum ):
                raise ChecksumException( 'Expected to get {0}. Got {1}'.format( calcChecksum, checksum ) )

        response.__class__ = MedtronicReceiveMessage
        
        if response.messageType == COM_D_COMMAND.TIME_RESPONSE:
            response.__class__ = PumpTimeResponseMessage
        elif response.messageType == COM_D_COMMAND.READ_HISTORY_INFO_RESPONSE:
            response.__class__ = PumpHistoryInfoResponseMessage
        elif response.messageType == COM_D_COMMAND.READ_PUMP_STATUS_RESPONSE:
            response.__class__ = PumpStatusResponseMessage
        elif response.messageType == COM_D_COMMAND.INITIATE_MULTIPACKET_TRANSFER:
            response.__class__ = MultiPacketSegment
        elif response.messageType == COM_D_COMMAND.MULTIPACKET_SEGMENT_TRANSMISSION:
            response.__class__ = MultiPacketSegment
        elif response.messageType == COM_D_COMMAND.END_HISTORY_TRANSMISSION:
            response.__class__ = MultiPacketSegment
        
        return response

    @property
    def messageType( self ):
        return struct.unpack( '>H', self.responsePayload[1:3] )[0]


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

class ReadLinkKeyResponseMessage( object ):
    @classmethod
    def decode( cls, message ):
        response = cls()
        response.responsePayload = message
        return response

    @property
    def packedLinkKey( self ):
        return struct.unpack( '>55s', self.responsePayload[0:55] )[0]

    def linkKey( self, serialNumber ):
        key = bytearray(b"")
        pos = ord_hack( serialNumber[-1:] ) & 7
        
        for it in range(16):
            if ( ord_hack( self.packedLinkKey[pos + 1] ) & 1) == 1:
                key.append(~ord_hack( self.packedLinkKey[pos] ) & 0xff)
            else:
                key.append(self.packedLinkKey[pos])

            if (( ord_hack( self.packedLinkKey[pos + 1] ) >> 1 ) & 1 ) == 0:
                pos += 3
            else:
                pos += 2

        return key

class PumpTimeResponseMessage( MedtronicReceiveMessage ):
    @classmethod
    def decode( cls, message, session ):
        response = MedtronicReceiveMessage.decode( message, session )
        if response.messageType != COM_D_COMMAND.TIME_RESPONSE:
            raise UnexpectedMessageException( "Expected to get a Time Response message '{0}'. Got {1}.".format( COM_D_COMMAND.TIME_RESPONSE, response.messageType ) )

        # Since we only add behaviour, we can cast this class to ourselves
        response.__class__ = PumpTimeResponseMessage
        return response

    @property
    def timeSet( self ):
        if self.responsePayload[3] == 0:
            return False
        else:
            return True

    @property
    def encodedDatetime( self ):
        return struct.unpack( '>Q', self.responsePayload[4:] )[0]

    @property
    def datetime( self ):
        dateTimeData = self.encodedDatetime
        return DateTimeHelper.decodeDateTime( dateTimeData )

    @property
    def offset( self ):
        dateTimeData = self.encodedDatetime
        return DateTimeHelper.decodeDateTimeOffset( dateTimeData )


class PumpHistoryInfoResponseMessage( MedtronicReceiveMessage ):
    @classmethod
    def decode( cls, message, session ):
        response = MedtronicReceiveMessage.decode( message, session )
        if response.messageType != COM_D_COMMAND.READ_HISTORY_INFO_RESPONSE:
            raise UnexpectedMessageException( "Expected to get a Time Response message '{0}'. Got {1}.".format( COM_D_COMMAND.READ_HISTORY_INFO_RESPONSE, response.messageType ) )
        # Since we only add behaviour, we can cast this class to ourselves
        response.__class__ = PumpHistoryInfoResponseMessage
        return response

    @property
    def historySize( self ):
        return struct.unpack( '>I', self.responsePayload[4:8] )[0]
    
    @property
    def encodedDatetimeStart( self ):
        return struct.unpack( '>Q', self.responsePayload[8:16] )[0]

    @property
    def encodedDatetimeEnd( self ):
        return struct.unpack( '>Q', self.responsePayload[16:24] )[0]    

    @property
    def datetimeStart( self ):
        dateTimeData = self.encodedDatetimeStart
        return DateTimeHelper.decodeDateTime( dateTimeData )

    @property
    def datetimeEnd( self ):
        dateTimeData = self.encodedDatetimeEnd
        return DateTimeHelper.decodeDateTime( dateTimeData )

class MultiPacketSegment( MedtronicReceiveMessage ):
    @classmethod
    def decode( cls, message, session ):
        response = MedtronicReceiveMessage.decode( message, session )
        # Since we only add behaviour, we can cast this class to ourselves
        response.__class__ = MultiPacketSegment
        return response

    @property
    def packetNumber( self ):
        return struct.unpack( '>H', self.responsePayload[3:5] )[0]
    
    @property
    def payload( self ):
        return self.responsePayload[5:]

    @property
    def segmentSize( self ):
        return struct.unpack( '>I', self.responsePayload[3:7] )[0]

    @property
    def packetSize( self ):
        return struct.unpack( '>H', self.responsePayload[7:9] )[0]

    @property
    def lastPacketSize( self ):
        return struct.unpack( '>H', self.responsePayload[9:11] )[0]

    @property
    def packetsToFetch( self ):
        return struct.unpack( '>H', self.responsePayload[11:13] )[0]

class PumpStatusResponseMessage( MedtronicReceiveMessage ):
    MMOL = 1
    MGDL = 2

    @classmethod
    def decode( cls, message, session ):
        response = MedtronicReceiveMessage.decode( message, session )
        if response.messageType != COM_D_COMMAND.READ_PUMP_STATUS_RESPONSE:
            raise UnexpectedMessageException( "Expected to get a Status Response message '{0}'. Got {1}.".format( COM_D_COMMAND.READ_PUMP_STATUS_RESPONSE, response.messageType ) )

        # Since we only add behaviour, we can cast this class to ourselves
        response.__class__ = PumpStatusResponseMessage
        return response

    @property
    def wholePayloadHex(self):
        return binascii.hexlify(self.responsePayload).upper()

    @property
    def currentBasalRate( self ):
        return float( struct.unpack( '>I', self.responsePayload[0x1b:0x1f] )[0] ) / 10000

    @property
    def tempBasalRate( self ):
        return float( struct.unpack( '>H', self.responsePayload[0x21:0x23] )[0] ) / 10000

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
        return float( struct.unpack( '>I', self.responsePayload[0x31:0x35] )[0] ) / 10000

    @property
    def sensorBGL( self ):
        return int( struct.unpack( '>H', self.responsePayload[0x35:0x37] )[0] )

    @property
    def trendArrowValue(self):
        status = int( struct.unpack( '>B', self.responsePayload[0x40:0x41] )[0] )
        if status == 0x60:
            return 0
        elif status == 0xc0:
            return 3
        elif status == 0xa0:
            return 2
        elif status == 0x80:
            return 1
        elif status == 0x40:
            return -1
        elif status == 0x20:
            return -2
        elif status == 0x00:
            return -3
        else:
            return None

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
    def sensorStatusValue(self):
        status = int(struct.unpack('>B', self.responsePayload[0x41:0x42])[0])
        return status

    @property
    def sensorStatus(self):
        status = int(struct.unpack('>B', self.responsePayload[0x41:0x42])[0])
        if status == 0x00:
            return "No sensor"
        elif status & 0x01 == 0x01:
            return "Calibrating 0x{:02X}".format(status)
        elif status & 0x02 == 0x02:
            return "Calibration complete 0x{:02X}".format(status)
        elif status & 0x04 == 0x04:
            return "SG value unavailable 0x{:02X}".format(status)
        else:
            return "Unknown sensor status: 0x{:02X}".format(status)
        return status

    @property
    def sensorControl(self):
        status = int(struct.unpack('>B', self.responsePayload[0x42:0x43])[0])
        return "0x{0:02X} ({0:08b})".format(status)
        return status

    @property
    def sensorControlValue(self):
        status = int(struct.unpack('>B', self.responsePayload[0x42:0x43])[0])
        return status

    @property
    def sensorCalibrationMinutesRemaining(self):
        minutes = int(struct.unpack('>H', self.responsePayload[0x43:0x45])[0])
        return minutes

    @property
    def sensorBatteryPercent(self):
        battery_percent = 100 * (0x0F & int(struct.unpack('>B', self.responsePayload[0x45:0x46])[0])) / 0x0F
        return battery_percent

    @property
    def sensorBGLTimestamp( self ):
        dateTimeData = struct.unpack( '>Q', self.responsePayload[55:63] )[0]
        return DateTimeHelper.decodeDateTime( dateTimeData )

    @property
    def recentBolusWizard( self ):
        if self.responsePayload[72] == 0:
            return False
        else:
            return True

    @property
    def bolusWizardBGL( self ):
        return struct.unpack( '>H', self.responsePayload[73:75] )[0]

class BeginEHSMMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        payload = struct.pack( '>B', 0x00 )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.HIGH_SPEED_MODE_COMMAND, session, payload )

class FinishEHSMMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        payload = struct.pack( '>B', 0x01 )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.HIGH_SPEED_MODE_COMMAND, session, payload )

class PumpTimeRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.TIME_REQUEST, session )

class PumpStatusRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.READ_PUMP_STATUS_REQUEST, session )

class PumpHistoryInfoRequestMessage( MedtronicSendMessage ):
    def __init__( self, session, dateStart, dateEnd, dateOffset, requestType = HISTORY_DATA_TYPE.PUMP_DATA):
        histDataType_PumpData = requestType
        fromRtc = DateTimeHelper.rtcFromDate(dateStart, dateOffset)
        toRtc = DateTimeHelper.rtcFromDate(dateEnd, dateOffset)
        payload = struct.pack( '>BBIIH', histDataType_PumpData, 0x04, fromRtc, toRtc, 0x00 )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.READ_HISTORY_INFO_REQUEST, session, payload )

class PumpHistoryRequestMessage( MedtronicSendMessage ):
    def __init__( self, session, dateStart, dateEnd, dateOffset, requestType = HISTORY_DATA_TYPE.PUMP_DATA ):
        histDataType_PumpData = requestType
        fromRtc = DateTimeHelper.rtcFromDate(dateStart, dateOffset)
        toRtc = DateTimeHelper.rtcFromDate(dateEnd, dateOffset)
        payload = struct.pack( '>BBIIH', histDataType_PumpData, 0x04, fromRtc, toRtc, 0x00 )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.READ_HISTORY_REQUEST, session, payload )

class AckMultipacketRequestMessage( MedtronicSendMessage ):
    SEGMENT_COMMAND__INITIATE_TRANSFER = COM_D_COMMAND.INITIATE_MULTIPACKET_TRANSFER
    SEGMENT_COMMAND__SEND_NEXT_SEGMENT = COM_D_COMMAND.MULTIPACKET_SEGMENT_TRANSMISSION
    
    def __init__( self, session, segmentCommand ):
        payload = struct.pack( '>H', segmentCommand )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.ACK_MULTIPACKET_COMMAND, session, payload )
    
class BasicNgpParametersRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.NGP_PARAMETER_REQUEST, session )

class DeviceCharacteristicsRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.DEVICE_CHARACTERISTICS_REQUEST, session )

class SuspendResumeRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        # TODO: Bug? Shall the payload be passed to the message, or not needed?
        payload = struct.pack( '>B', 0x01 )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.SUSPEND_RESUME_REQUEST, session )

class PumpTempBasalRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.TEMP_BASAL_REQUEST, session )

class PumpBolusesRequestMessage( MedtronicSendMessage ):
    def __init__( self, session ):
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.BOLUSES_REQUEST, session )

class PumpRemoteBolusRequestMessage( MedtronicSendMessage ):
    def __init__( self, session, bolusID, amount, execute ):
        unknown1 = 0 # ??
        unknown2 = 0 # Square Wave amount?
        unknown3 = 0 # Square Wave length?
        payload = struct.pack( '>BBHHBH', bolusID, execute, unknown1, amount * 10000, unknown2, unknown3 )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.REMOTE_BOLUS_REQUEST, session, payload )

class Type405RequestMessage( MedtronicSendMessage ):
    def __init__( self, session, pumpDateTime ):
        payload = struct.pack( '>BQ', 0x01, pumpDateTime )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.REQUEST_0x0405, session, payload )

class Type124RequestMessage( MedtronicSendMessage ):
    def __init__( self, session, pumpDateTime ):
        payload = struct.pack( '>QBB', pumpDateTime, 0x00, 0xFF )
        MedtronicSendMessage.__init__( self, COM_D_COMMAND.REQUEST_0x0124, session, payload )

class BayerBinaryMessage( object ):
    def __init__( self, messageType=None, session=None, payload=None ):
        self.payload = payload
        self.session = session
        if messageType and self.session:
            self.envelope = struct.pack( '<BB6s10sBI5sI', 0x51, 3, b'000000', b'\x00' * 10,
                messageType, self.session.bayerSequenceNumber, b'\x00' * 5, 
                len( self.payload ) if self.payload else 0 )
            self.envelope += struct.pack( 'B', self.makeMessageCrc() )

    def makeMessageCrc( self ):
        checksum = 0
        for x in self.envelope[0:32]:
            checksum += ord_hack(x)
        #checksum = sum( bytearray(self.envelope[0:32], 'utf-8') )

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
        response.envelope = message[0:33]
        response.payload = message[33:] 

        checksum = message[32]
        calcChecksum = response.makeMessageCrc()
        if( checksum != calcChecksum ):
            logger.error('ChecksumException: Expected to get {0}. Got {1}'.format( calcChecksum, checksum ))
            raise ChecksumException( 'Expected to get {0}. Got {1}'.format( calcChecksum, checksum ) )

        return response
    
    @property
    def linkDeviceOperation( self ):
        return ord_hack(self.envelope[18])

    # HACK: This is just a debug try, session param shall not be there    
    def checkLinkDeviceOperation( self, expectedValue, session = None ):
        if self.linkDeviceOperation != expectedValue:
            logger.debug("### checkLinkDeviceOperation BayerBinaryMessage.envelope: {0}".format(binascii.hexlify(self.envelope)))
            logger.debug("### checkLinkDeviceOperation BayerBinaryMessage.payload: {0}".format(binascii.hexlify(self.payload)))
            # HACK: This is just a debug try
            if self.linkDeviceOperation == 0x80:
                response = MedtronicReceiveMessage.decode( self.payload, session )
                logger.warning("#### Message type of caught 0x80: 0x{0:x}".format(response.messageType))
            raise UnexpectedMessageException( "Expected to get linkDeviceOperation {0:x}. Got {1:x}".format( expectedValue, self.linkDeviceOperation ) )

class Medtronic600SeriesDriver( object ):
    USB_BLOCKSIZE = 64
    USB_VID = 0x1a79
    USB_PID = 0x6210
    MAGIC_HEADER = b'ABC'
    
    ERROR_CLEAR_TIMEOUT_MS   = 25000
    PRESEND_CLEAR_TIMEOUT_MS = 50
    READ_TIMEOUT_MS          = 10000
    CNL_READ_TIMEOUT_MS      = 2000

    CHANNELS = [ 0x14, 0x11, 0x0e, 0x17, 0x1a ] # In the order that the CareLink applet requests them

    session = None
    offset = -1592387759; # Just read out of my pump. Shall be overwritten by reading date/time from pump

    def __init__( self ):
        self.session = MedtronicSession()
        self.device = None

        self.deviceInfo = None

    def openDevice( self ):
        logger.info("# Opening device")
        self.device = hid.device()
        self.device.open( self.USB_VID, self.USB_PID )

        logger.info("Manufacturer: %s" % self.device.get_manufacturer_string())
        logger.info("Product: %s" % self.device.get_product_string())
        logger.info("Serial No: %s" % self.device.get_serial_number_string())
    
    def closeDevice( self ):
        logger.info("# Closing device")
        self.device.close()

    def readMessage( self, timeout_ms=READ_TIMEOUT_MS ):
        payload = bytearray()
        bytesRead = 0
        payloadSize = 0
        expectedSize = 0
        first = True
        
        while first or (bytesRead > 0 and payloadSize == self.USB_BLOCKSIZE-4 and len(payload) != expectedSize):
            t = timeout_ms if first else 10000
            data = self.device.read( self.USB_BLOCKSIZE, timeout_ms = t )
            first = False
            if data:
                bytesRead = len(data)
                payloadSize = data[3]
                if( bytearray( data[0:3] ) != self.MAGIC_HEADER ):
                    logger.error('Recieved invalid USB packet')
                    raise RuntimeError( 'Recieved invalid USB packet')
                payload.extend( data[4:data[3] + 4] )

                # get the expected size for 0x80 or 0x81 messages as they may be on a block boundary
                if expectedSize == 0 and data[3] >= 0x21  and ((data[0x12 + 4] & 0xFF == 0x80) or (data[0x12 + 4] & 0xFF == 0x81)):
                    expectedSize = 0x21 + ((data[0x1C + 4] & 0x00FF) | (data[0x1D + 4] << 8 & 0xFF00))
               
                logger.debug('READ: bytesRead={0}, payloadSize={1}, expectedSize={2}'.format(bytesRead, payloadSize, expectedSize))

            else:
                #logger.warning('Timeout waiting for message')
                raise TimeoutException( 'Timeout waiting for message' )

        # logger.debug("READ: " + binascii.hexlify( payload )) # Debugging
        return payload

    def sendMessage( self, payload ):
        
        # Clear any message in the receive buffer
        self.clearMessage(timeout_ms=self.PRESEND_CLEAR_TIMEOUT_MS)
        
        # Split the message into 60 byte chunks
        for packet in [ payload[ i: i+60 ] for i in range( 0, len( payload ), 60 ) ]:
            message = struct.pack( '>3sB', self.MAGIC_HEADER, len( packet ) ) + packet
            self.device.write( bytearray( message ) )
            #logger.debug("SEND: " + binascii.hexlify( message )) # Debugging

    # Intercept unexpected messages from the CNL
    # These usually come from pump requests as it can occasionally resend message responses several times 
    # (possibly due to a missed CNL ACK during CNL-PUMP comms?) mostly noted on the higher radio channels, 
    # channel 26 shows this the most
    # If these messages are not cleared the CNL will likely error needing to be unplugged to reset as it 
    # expects them to be read before any further commands are sent

    # post-clear: send request --> read and drop any message that is not the expected 0x81 response
    # this works if only one message needs to be cleared with the next being the expected 0x81
    # if there is more then one message to be cleared then there is no 0x81 response and the CNL will E86 error
    #
    # pre-clear: clear all messages in stream until timeout --> send request
    # consistently stable even with a small timeout, clears multiple messages with very rare miss
    # which will get caught using the post-clear method as fail-safe

    def clearMessage(self, timeout_ms=ERROR_CLEAR_TIMEOUT_MS):
       
        logger.debug("## CLEAR: timeout={0}".format(timeout_ms))
        
        count = 0
        cleared = False

        while not cleared:
            try:
                payload = self.readMessage(timeout_ms)
                count+=1

                # the following are always seen as the end of an incoming stream and can be considered as completed clear indicators

                # check for 'no pump response'
                # 55 | 0B | 00 00 | 00 02 00 00 03 00 00
                if len(payload) == 0x2E and payload[0x21] == 0x55 and payload[0x23] == 0x00 and payload[0x24] == 0x00 and payload[0x26] == 0x02 and payload[0x29] == 0x03:
                    logger.warning("## CLEAR: got 'no pump response' message indicating stream cleared")
                    cleared = True

                elif len(payload) == 0x30 and payload[0x21] == 0x55  and payload[0x24] == 0x00 and payload[0x25] == 0x00 and payload[0x26] == 0x02 and payload[0x29] == 0x02 and payload[0x2B] == 0x01:
                    logger.warning("## CLEAR: got message containing '55 0D 00 00 00 02 00 00 02 00 01 XX XX' (lost pump connection)")
                    cleared = True

                # check for 'non-standard network connect'
                # standard 'network connect' 0x80 response
                # 55 | 2C | 00 04 | xx xx xx xx xx | 02 | xx xx xx xx xx xx xx xx | 82 | 00 00 00 00 00 | 07 | 00 | xx | xx xx xx xx xx xx xx xx | 42 | 00 00 00 00 00 00 00 | xx
                # 55 | size | type | pump serial | ... | pump mac | ... | ... | ... | rssi | cnl mac | ... | ... | channel
                # difference to the standard 'network connect' response
                # -- | -- | 00 00 | -- -- -- -- -- | -- | -- -- -- -- -- -- -- -- | 83 | -- -- -- -- -- | -- | xx | -- | -- -- -- -- -- -- -- -- | 43 | -- -- -- -- -- -- -- | --
                elif len(payload) == 0x4F and payload[0x21] == 0x55 and payload[0x23] == 0x00 and payload[0x24] == 0x00 and (payload[0x33] & 0xFF) == 0x83 and payload[0x44] == 0x43:
                    logger.warning("## CLEAR: got 'non-standard network connect' message indicating stream cleared")
                    cleared = True

            except TimeoutException:
                cleared = True

        if count > 0:
           logger.warning("## CLEAR: message stream cleared " + str(count) + " messages.")

        return count
    
    def readResponse0x80(self):
       
        logger.debug("## readResponse0x80")
        
        payload = self.readMessage()

        # minimum 0x80 message size?
        if len(payload) <= 0x21:
            logger.error("readResponse0x80: message size <= 0x21")
            self.clearMessage()
            #raise UnexpectedMessageException(("0x80 response message size less then expected")

        # 0x80 message?
        if (payload[0x12] & 0xFF) != 0x80:
            logger.error("readResponse0x80: message not a 0x80")
            self.clearMessage()
            raise UnexpectedMessageException("0x80 response message not a 0x80")

        # message and internal payload size correct?
        if len(payload) != (0x21 + payload[0x1C] & 0x00FF | payload[0x1D] << 8 & 0xFF00):
            logger.error("readResponse0x80: message size mismatch")
            self.clearMessage()
            raise UnexpectedMessageException("0x80 response message size mismatch")

        # 1 byte response? (generally seen as a 0x00 or 0xFF, unknown meaning and high risk of CNL E86 follows)
        if len(payload) == 0x22:
            logger.error("readResponse0x80: message with 1 byte internal payload")
            # do not retry, end the session
            raise UnexpectedMessageException("0x80 response message internal payload is 0x..., connection lost")

        # internal 0x55 payload?
        elif payload[0x21] != 0x55:
            logger.error("readResponse0x80: message no internal 0x55")
            self.clearMessage()
            # do not retry, end the session
            raise UnexpectedMessageException("0x80 response message internal payload not a 0x55, connection lost")

        if len(payload) == 0x2E:
            # no pump response?
            if payload[0x24] == 0x00 and payload[0x25] == 0x00 and payload[0x26] == 0x02 and payload[0x27] == 0x00:
                logger.warning("## readResponse0x80: message containing '55 0B 00 00 00 02 00 00 03 00 00' (no pump response)")
                # stream is always clear after this message
                raise UnexpectedMessageException("no response from pump")

            # no connect response?
            elif payload[0x24] == 0x00 and payload[0x25] == 0x20 and payload[0x26] == 0x00 and payload[0x27] == 0x00:
                logger.debug("## readResponse0x80: message containing '55 0B 00 00 20 00 00 00 03 00 00' (no connect)")

            # bad response?
            # seen during multipacket transfers, may indicate a full CNL receive buffer
            elif payload[0x24] == 0x06 and (payload[0x25] & 0xFF) == 0x88 and payload[0x26] == 0x00 and payload[0x27] == 0x65:
                logger.warning("## readResponse0x80: message containing '55 0B 00 06 88 00 65 XX 03 00 00' (bad response)")

        # lost pump connection?
        elif len(payload) == 0x30 and payload[0x24] == 0x00 and payload[0x25] == 0x00 and payload[0x26] == 0x02 and payload[0x29] == 0x02 and payload[0x2B] == 0x01:
            logger.error("readResponse0x80: message containing '55 0D 00 00 00 02 00 00 02 00 01 XX XX' (lost pump connection)")
            self.clearMessage()
            # do not retry, end the session
            raise UnexpectedMessageException("connection lost")

        # connection
        elif len(payload) == 0x4F:
            # network connect
            # 55 | 2C | 00 04 | xx xx xx xx xx | 02 | xx xx xx xx xx xx xx xx | 82 | 00 00 00 00 00 | 07 | 00 | xx | xx xx xx xx xx xx xx xx | 42 | 00 00 00 00 00 00 00 | xx
            # 55 | size | type | pump serial | ... | pump mac | ... | ... | ... | rssi | cnl mac | ... | ... | channel
            if payload[0x24] == 0x04 and (payload[0x33] & 0xFF) == 0x82 and payload[0x44] == 0x42:
                logger.debug("## readResponse0x80: message containing network connect (pump connected)")

            # non-standard network connect
            # -- | -- | 00 00 | -- -- -- -- -- | -- | -- -- -- -- -- -- -- -- | 83 | -- -- -- -- -- | -- | xx | -- | -- -- -- -- -- -- -- -- | 43 | -- -- -- -- -- -- -- | --
            elif payload[0x24] == 0x00 and (payload[0x33] & 0xFF) == 0x83 and payload[0x44] == 0x43:
                logger.error("readResponse0x80: message containing non-standard network connect (lost pump connection)")
                # stream is always clear after this message
                # do not retry, end the session
                raise UnexpectedMessageException("connection lost")
     
        return BayerBinaryMessage.decode(payload)
    
    def readResponse0x81(self):

        logger.debug("## readResponse0x81")
        
        try:
            # an 0x81 response is always expected after sending a request
            # keep reading until we get it or timeout
            while True:
                payload = self.readMessage()           # Read USB packet payload
                if len(payload) < 0x21:                # Check for min length
                    logger.warning("## readResponse0x81: message size less then expected, length = {0}".format(len(payload)))
                elif (payload[0x12] & 0xFF) != 0x81:   # Check operation byte (expect 0x81 SEND_MESSAGE_RESPONSE)
                    logger.warning("## readResponse0x81: message not a 0x81, got a 0x{0:x}".format(payload[0x12]))
                else:
                    break
        
        except TimeoutException:                       # Timeout in readMessage()
            # ugh... there should always be a CNL 0x81 response and if we don't get one
            # it usually ends with a E86 / E81 error on the CNL needing a unplug/plug cycle
            logger.error("readResponse0x81: timeout waiting for 0x81 response")
            raise TimeoutException("Timeout waiting for 0x81 response")

        # Perform more checks

        # empty response?
        if len(payload) <= 0x21:
            logger.error("readResponse0x81: message size <= 0x21")
            self.clearMessage()
            # do not retry, end the session
            raise UnexpectedMessageException("0x81 response was empty, connection lost")
        
        # message and internal payload size correct?
        elif len(payload) != (0x21 + payload[0x1C] & 0x00FF | payload[0x1D] << 8 & 0xFF00):
            logger.error("readResponse0x81: message size mismatch")
            self.clearMessage()
            raise UnexpectedMessageException("0x81 response message size mismatch")
        
        # internal 0x55 payload?
        elif payload[0x21] != 0x55:
            logger.error("readResponse0x81: message no internal 0x55")
            self.clearMessage()
            raise UnexpectedMessageException("0x81 response was not a 0x55 message")

        # state flag?
        # standard response:
        # 55 | 0D   | 00 04 | 00 00 00 00 03 00 01 | xx | xx
        # 55 | size | type  | ... | seq | state
        if len(payload) == 0x30:
            if payload[0x2D] == 0x04:
                logger.warning("## readResponse0x81: message [0x2D]==0x04 (noisy/busy)")
            
            elif payload[0x2D] != 0x02:
                logger.error("readResponse0x81: message [0x2D]!=0x02 (unknown state)")
                self.clearMessage()
                raise UnexpectedMessageException("0x81 unknown state flag")
            
        # connection
        elif len(payload) == 0x27 and payload[0x23] == 0x00 and payload[0x24] == 0x00:
            logger.warning("## readResponse0x81: message containing '55 04 00 00' (network not connected)")
        else:
            logger.warning("## readResponse0x81: unknown 0x55 message type")

        return payload

    @property
    def deviceSerial( self ):
        if not self.deviceInfo:
            return None
        else:
            return self.deviceInfo[0][4][3][1]

    def getDeviceInfo( self ):
        logger.info("# Read Device Info")
        self.sendMessage( struct.pack( '>B', 0x58 ) )

        while True:
            try:
                logger.debug(' ## Read first message')
                msg1 = self.readMessage()
                
                logger.debug(' ## Read second message')
                msg2 = self.readMessage()

                if astm.codec.is_chunked_message( msg1 ):
                    logger.debug(' ## First message is ASTM message')
                    astm_msg = msg1
                    ctrl_msg = msg2
                elif astm.codec.is_chunked_message( msg2 ):
                    logger.debug(' ## Second message is ASTM message')
                    astm_msg = msg2
                    ctrl_msg = msg1
                else:
                    logger.error('readDeviceInfo: Expected to get an ASTM message, but got {0} instead'.format( binascii.hexlify( msg ) ))
                    raise RuntimeError( 'Expected to get an ASTM message, but got {0} instead'.format( binascii.hexlify( msg ) ) )

                controlChar = ascii['ENQ']
                if len( ctrl_msg ) > 0 and ctrl_msg[0] != controlChar:
                    logger.error(' ### getDeviceInfo: Expected to get an 0x{0:x} control character, got message with length {1} and control char 0x{1:x}'.format( controlChar, len( ctrl_msg ), ctrl_msg[0] ))
                    raise RuntimeError( 'Expected to get an 0x{0:x} control character, got message with length {1} and control char 0x{1:x}'.format( controlChar, len( ctrl_msg ), ctrl_msg[0] ) )
                 
                self.deviceInfo = astm.codec.decode( bytes( astm_msg ) )
                self.session.stickSerial = self.deviceSerial
                
                break

            except TimeoutException:
                self.sendMessage( struct.pack( '>B', ascii['EOT'] ) )

    def checkControlMessage( self, controlChar ):
        msg = self.readMessage()
        if len( msg ) > 0 and msg[0] != controlChar:
            logger.error(' ### checkControlMessage: Expected to get an 0x{0:x} control character, got message with length {1} and control char 0x{1:x}'.format( controlChar, len( msg ), msg[0] ))
            raise RuntimeError( 'Expected to get an 0x{0:x} control character, got message with length {1} and control char 0x{1:x}'.format( controlChar, len( msg ), msg[0] ) )

    def enterControlMode( self ):
        logger.info("# enterControlMode")
        self.sendMessage( struct.pack( '>B', ascii['NAK'] ) )
        self.checkControlMessage( ascii['EOT'] )
        self.sendMessage( struct.pack( '>B', ascii['ENQ'] ) )
        self.checkControlMessage( ascii['ACK'] )

    def exitControlMode( self ):
        logger.info("# exitControlMode")
        try:
            self.sendMessage( struct.pack( '>B', ascii['EOT'] ) )
            self.checkControlMessage( ascii['ENQ'] )
        except Exception:
            logger.warning("Unexpected error by exitControlMode, ignoring", exc_info = True);

    def enterPassthroughMode( self ):
        logger.info("# enterPassthroughMode")
        self.sendMessage( struct.pack( '>2s', b'W|' ) )
        self.checkControlMessage( ascii['ACK'] )
        self.sendMessage( struct.pack( '>2s', b'Q|' ) )
        self.checkControlMessage( ascii['ACK'] )
        self.sendMessage( struct.pack( '>2s', b'1|' ) )
        self.checkControlMessage( ascii['ACK'] )

    def exitPassthroughMode( self ):
        logger.info("# exitPassthroughMode")
        try:
            self.sendMessage( struct.pack( '>2s', b'W|' ) )
            self.checkControlMessage( ascii['ACK'] )
            self.sendMessage( struct.pack( '>2s', b'Q|' ) )
            self.checkControlMessage( ascii['ACK'] )
            self.sendMessage( struct.pack( '>2s', b'0|' ) )
            self.checkControlMessage( ascii['ACK'] )
        except Exception:
            logger.warning("Unexpected error by exitPassthroughMode, ignoring", exc_info = True);

    def openConnection( self ):
        logger.info("# Request Open Connection")

        mtMessage = binascii.unhexlify( self.session.HMAC )
        bayerMessage = BayerBinaryMessage( 0x10, self.session, mtMessage )
        self.sendMessage( bayerMessage.encode() )
        self.readMessage()

    def closeConnection( self ):
        logger.info("# Request Close Connection")
        try:
            mtMessage = binascii.unhexlify( self.session.HMAC )
            bayerMessage = BayerBinaryMessage( 0x11, self.session, mtMessage )
            self.sendMessage( bayerMessage.encode() )
            self.readMessage()
        except Exception:
            logger.warning("Unexpected error by requestCloseConnection, ignoring", exc_info = True);

    def readInfo( self ):
        logger.info("# Request Read Info")
        bayerMessage = BayerBinaryMessage( 0x14, self.session )
        self.sendMessage( bayerMessage.encode() )
        response = BayerBinaryMessage.decode( self.readMessage() ) # The response is a 0x14 as well
        info = ReadInfoResponseMessage.decode( response.payload )
        self.session.linkMAC = info.linkMAC
        self.session.pumpMAC = info.pumpMAC

    def readLinkKey( self ):
        logger.info("# Request Read Link Key")
        bayerMessage = BayerBinaryMessage( 0x16, self.session )
        self.sendMessage( bayerMessage.encode() )
        response = BayerBinaryMessage.decode( self.readMessage() ) # The response is a 0x14 as well
        keyRequest = ReadLinkKeyResponseMessage.decode( response.payload )
        self.session.KEY = bytes(keyRequest.linkKey( self.session.stickSerial ))
        logger.debug("LINK KEY: {0}".format(binascii.hexlify(self.session.KEY)))

    def negotiateChannel( self ):
        logger.info("# Negotiate pump comms channel")

        # Scan the last successfully connected channel first, since this could save us negotiating time
        for self.session.radioChannel in [ self.session.config.lastRadioChannel ] + self.CHANNELS:
            logger.debug("Negotiating on channel {0}".format( self.session.radioChannel ))

            mtMessage = ChannelNegotiateMessage( self.session )

            bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
            self.sendMessage( bayerMessage.encode() )
            self.readResponse0x81()
            response = self.readResponse0x80()
            if len( response.payload ) > 13:
                # Check that the channel ID matches
                responseChannel = response.payload[43]
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

    def beginEHSM( self ):
        logger.info("# Begin Extended High Speed Mode Session")
        mtMessage = BeginEHSMMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81() # The Begin EHSM only has an 0x81 response

    def finishEHSM( self ):
        logger.info("# Finish Extended High Speed Mode Session")
        try:
            mtMessage = FinishEHSMMessage( self.session )
    
            bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
            self.sendMessage( bayerMessage.encode() )
            try:
                self.readResponse0x81() # The Finish EHSM only has an 0x81 response
            except:
                # if does not come, ignore...
                pass
        except Exception:
            logger.warning("Unexpected error by finishEHSM, ignoring", exc_info = True);

    def getBayerBinaryMessage(self, expectedLinkDeviceOperation):
        messageReceived = False
        message = None
        while messageReceived == False:
            message = BayerBinaryMessage.decode(self.readMessage())
            if message.linkDeviceOperation == expectedLinkDeviceOperation:
                messageReceived = True
            else:
                logger.warning("## getBayerBinaryMessage: waiting for message 0x{0:x}, got 0x{1:x}".format(expectedLinkDeviceOperation, message.linkDeviceOperation))
        return message

    def getMedtronicMessage(self, expectedMessageTypes):
        messageReceived = False
        medMessage = None
        while messageReceived == False:
            message = self.readResponse0x80()
            medMessage = MedtronicReceiveMessage.decode(message.payload, self.session)
            if medMessage.messageType in expectedMessageTypes:
                messageReceived = True
            else:
                logger.warning("## getMedtronicMessage: waiting for message of [{0}], got 0x{1:x}".format(''.join('%04x '%i for i in expectedMessageTypes) , medMessage.messageType))
        return medMessage

    def getPumpTime( self ):
        logger.info("# Get Pump Time")
        mtMessage = PumpTimeRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        result = self.getMedtronicMessage([COM_D_COMMAND.TIME_RESPONSE])
        self.offset = result.offset;
        return result

    def getPumpStatus( self ):
        logger.info("# Get Pump Status")
        mtMessage = PumpStatusRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.getMedtronicMessage([COM_D_COMMAND.READ_PUMP_STATUS_RESPONSE])
        return response

    def getPumpHistoryInfo( self, dateStart, dateEnd, requestType = HISTORY_DATA_TYPE.PUMP_DATA ):
        logger.info("# Get Pump History Info")
        mtMessage = PumpHistoryInfoRequestMessage( self.session, dateStart, dateEnd, self.offset, requestType )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.getMedtronicMessage([COM_D_COMMAND.READ_HISTORY_INFO_RESPONSE])
        return response

    def getPumpHistory( self, expectedSize, dateStart, dateEnd, requestType = HISTORY_DATA_TYPE.PUMP_DATA ):
        logger.info("# Get Pump History")
        allSegments = []
        mtMessage = PumpHistoryRequestMessage( self.session, dateStart, dateEnd, self.offset, requestType )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81() 

        transmissionCompleted = False
        while transmissionCompleted != True:
            responseSegment = self.getMedtronicMessage([COM_D_COMMAND.HIGH_SPEED_MODE_COMMAND, COM_D_COMMAND.INITIATE_MULTIPACKET_TRANSFER, COM_D_COMMAND.MULTIPACKET_SEGMENT_TRANSMISSION, COM_D_COMMAND.END_HISTORY_TRANSMISSION])
                            
            if responseSegment.messageType == COM_D_COMMAND.HIGH_SPEED_MODE_COMMAND:
                logger.debug("## getPumpHistory consumed HIGH_SPEED_MODE_COMMAND")
                pass
            elif responseSegment.messageType == COM_D_COMMAND.INITIATE_MULTIPACKET_TRANSFER:
                logger.debug("## getPumpHistory got INITIATE_MULTIPACKET_TRANSFER")
                logger.debug("## getPumpHistory INITIATE_MULTIPACKET_TRANSFER.segmentSize: {0}".format(responseSegment.segmentSize))
                logger.debug("## getPumpHistory INITIATE_MULTIPACKET_TRANSFER.packetSize: {0}".format(responseSegment.packetSize))
                logger.debug("## getPumpHistory INITIATE_MULTIPACKET_TRANSFER.lastPacketSize: {0}".format(responseSegment.lastPacketSize))
                logger.debug("## getPumpHistory INITIATE_MULTIPACKET_TRANSFER.packetsToFetch: {0}".format(responseSegment.packetsToFetch))
                segmentParams = responseSegment
                packets = [None] * responseSegment.packetsToFetch
                numPackets = 0
                ackMessage = AckMultipacketRequestMessage(self.session, AckMultipacketRequestMessage.SEGMENT_COMMAND__INITIATE_TRANSFER)
                bayerAckMessage = BayerBinaryMessage( 0x12, self.session, ackMessage.encode() )
                self.sendMessage( bayerAckMessage.encode() )
                self.readResponse0x81()

            elif responseSegment.messageType == COM_D_COMMAND.MULTIPACKET_SEGMENT_TRANSMISSION:
                logger.debug("## getPumpHistory got MULTIPACKET_SEGMENT_TRANSMISSION")
                logger.debug("## getPumpHistory responseSegment.packetNumber: {0}".format(responseSegment.packetNumber))
                if responseSegment.packetNumber != (segmentParams.packetsToFetch - 1) and len(responseSegment.payload) != segmentParams.packetSize:                
                    logger.warning("## WARNING - packet length invalid, skipping. Expected {0}, got {1}, for packet {2}/{3}".format(segmentParams.packetSize, len(responseSegment.payload), responseSegment.packetNumber, responseSegment.segmentParams))
                    continue
                if responseSegment.packetNumber == segmentParams.packetsToFetch - 1 and len(responseSegment.payload) != segmentParams.lastPacketSize:                
                    logger.warning("## WARNING - last packet length invalid, skipping. Expected {0}, got {1}, for packet {2}/{3}".format(segmentParams.lastPacketSize, len(responseSegment.payload), responseSegment.packetNumber, responseSegment.segmentParams))
                    continue
                if responseSegment.packetNumber < 0 or responseSegment.packetNumber >= segmentParams.packetsToFetch:
                    logger.warning("## WARNING - received packed out of expected range. Packet {2}/{3}".format(responseSegment.packetNumber, responseSegment.segmentParams))
                    continue                    
                if packets[responseSegment.packetNumber] == None:
                    numPackets = numPackets + 1
                    packets[responseSegment.packetNumber] = responseSegment.payload
                else:
                    logger.warning("## WARNING - packet duplicated")
                    
                if numPackets == segmentParams.packetsToFetch:
                    logger.debug("## All packets there")
                    logger.debug("## Requesting next segment")
                    allSegments.append(packets)
                    
                    #request next segment
                    ackMessage = AckMultipacketRequestMessage(self.session, AckMultipacketRequestMessage.SEGMENT_COMMAND__SEND_NEXT_SEGMENT)
                    bayerAckMessage = BayerBinaryMessage( 0x12, self.session, ackMessage.encode() )
                    self.sendMessage( bayerAckMessage.encode() )
                    self.readResponse0x81()
            elif responseSegment.messageType == COM_D_COMMAND.END_HISTORY_TRANSMISSION:
                logger.debug("## getPumpHistory got END_HISTORY_TRANSMISSION")
                transmissionCompleted = True
            else:          
                logger.warning("## getPumpHistory !!! UNKNOWN MESSAGE !!!")
                logger.warning("## getPumpHistory response.messageType: {0:x}".format(responseSegment.messageType))

        if transmissionCompleted:
            return allSegments
        else:
            logger.error("Transmission finished, but END_HISTORY_TRANSMISSION did not arrive")
            raise DataIncompleteError("Transmission finished, but END_HISTORY_TRANSMISSION did not arrive")
        
    def decodePumpSegment(self, encodedFragmentedSegment, historyType = HISTORY_DATA_TYPE.PUMP_DATA):
        decodedBlocks = []
        segmentPayload = encodedFragmentedSegment[0]
        
        for idx in range(1, len(encodedFragmentedSegment)):        
            segmentPayload+= encodedFragmentedSegment[idx]        
        
        # Decompress the message
        if struct.unpack( '>H', segmentPayload[0:2])[0] == 0x030E:
            HEADER_SIZE = 12
            BLOCK_SIZE = 2048
            # It's an UnmergedHistoryUpdateCompressed response. We need to decompress it
            dataType = struct.unpack('>B', segmentPayload[2:3])[0] # Returns a HISTORY_DATA_TYPE
            historySizeCompressed = struct.unpack( '>I', segmentPayload[3:7])[0] #segmentPayload.readUInt32BE(0x03)
            logger.debug("Compressed: {0}".format(historySizeCompressed))
            historySizeUncompressed = struct.unpack( '>I', segmentPayload[7:11])[0] #segmentPayload.readUInt32BE(0x07)
            logger.debug("Uncompressed: {0}".format(historySizeUncompressed)) 
            historyCompressed = struct.unpack('>B', segmentPayload[11:12])[0]
            logger.debug("IsCompressed: {0}".format(historyCompressed))

            if dataType != historyType: # Check HISTORY_DATA_TYPE (PUMP_DATA: 2, SENSOR_DATA: 3)
                logger.error('History type in response: {0} {1}'.format(type(dataType), dataType)) 
                raise InvalidMessageError('Unexpected history type in response')

            # Check that we have the correct number of bytes in this message
            if len(segmentPayload) - HEADER_SIZE != historySizeCompressed:
                raise InvalidMessageError('Unexpected message size')


            blockPayload = None
            if historyCompressed > 0:
                blockPayload = lzo.decompress(segmentPayload[HEADER_SIZE:], False, historySizeUncompressed)
            else:
                blockPayload = segmentPayload[HEADER_SIZE:]


            if len(blockPayload) % BLOCK_SIZE != 0:
                raise InvalidMessageError('Block payload size is not a multiple of 2048')


            for i in range (0, len(blockPayload) // BLOCK_SIZE):
                blockSize = struct.unpack('>H', blockPayload[(i + 1) * BLOCK_SIZE - 4 : (i + 1) * BLOCK_SIZE - 2])[0] #blockPayload.readUInt16BE(((i + 1) * ReadHistoryCommand.BLOCK_SIZE) - 4)
                blockChecksum = struct.unpack('>H', blockPayload[(i + 1) * BLOCK_SIZE - 2 : (i + 1) * BLOCK_SIZE])[0] #blockPayload.readUInt16BE(((i + 1) * ReadHistoryCommand.BLOCK_SIZE) - 2)

                blockStart = i * BLOCK_SIZE
                blockData = blockPayload[blockStart : blockStart + blockSize]
                calculatedChecksum = MedtronicMessage.calculateCcitt(blockData)
                if blockChecksum != calculatedChecksum:
                    raise ChecksumError('Unexpected checksum in block')
                else:
                    decodedBlocks.append(blockData) 
        else:
            raise InvalidMessageError('Unknown history response message type')
        
        return decodedBlocks
    
    def decodeEvents(self, decodedBlocks):
        eventList = []
        for page in decodedBlocks:
            pos = 0;
    
            while pos < len(page):
                eventSize = struct.unpack('>B', page[pos + 2 : pos + 3])[0] # page[pos + 2];
                eventData = page[pos : pos + eventSize] # page.slice(pos, pos + eventSize);
                pos += eventSize
                eventList.extend(NGPHistoryEvent(eventData).eventInstance().allNestedEvents())
        return eventList
                
    def processPumpHistory( self, historySegments, historyType = HISTORY_DATA_TYPE.PUMP_DATA):
        historyEvents = []
        for segment in historySegments:
            decodedBlocks = self.decodePumpSegment(segment, historyType)
            historyEvents += self.decodeEvents(decodedBlocks) 
        for event in historyEvents:
            event.postProcess(historyEvents)
        return historyEvents

    def getTempBasalStatus( self ):
        logger.info("# Get Temp Basal Status")
        mtMessage = PumpTempBasalRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.readResponse0x80()
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def getBolusesStatus( self ):
        logger.info("# Get Boluses Status")
        mtMessage = PumpBolusesRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.readResponse0x80() 
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def getBasicParameters( self ):
        logger.info("# Get Basic Parameters")
        mtMessage = BasicNgpParametersRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.readResponse0x80()
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def do405Message( self, pumpDateTime ):
        logger.info("# Send Message Type 405")
        mtMessage = Type405RequestMessage( self.session, pumpDateTime )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81() 
        response = self.readResponse0x80()
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def do124Message( self, pumpDateTime ):
        logger.info("# Send Message Type 124")
        mtMessage = Type124RequestMessage( self.session, pumpDateTime )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.readResponse0x80() 
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def doRemoteBolus( self, bolusID, amount, execute ):
        logger.info("# Execute Remote Bolus")
        mtMessage = PumpRemoteBolusRequestMessage( self.session, bolusID, amount, execute )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        self.readResponse0x81()
        response = self.readResponse0x80() 
        return MedtronicReceiveMessage.decode( response.payload, self.session )

    def doRemoteSuspend( self ):
        logger.info("# Execute Remote Suspend")
        mtMessage = SuspendResumeRequestMessage( self.session )

        bayerMessage = BayerBinaryMessage( 0x12, self.session, mtMessage.encode() )
        self.sendMessage( bayerMessage.encode() )
        response81 = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x81
        logger.debug(binascii.hexlify( response81.payload ))

        response = BayerBinaryMessage.decode( self.readMessage() ) # Read the 0x80
        return MedtronicReceiveMessage.decode( response.payload, self.session )

def downloadPumpSession(downloadOperations):
    mt = Medtronic600SeriesDriver()
    mt.openDevice()
    try:
        mt.getDeviceInfo()
        logger.info("Device serial: {0}".format(mt.deviceSerial))
        mt.enterControlMode()
        try:
            mt.enterPassthroughMode()
            try:
                mt.openConnection()
                try:
                    mt.readInfo()
                    mt.readLinkKey()
                    try:
                        mt.negotiateChannel()
                    except:
                        logger.error("downloadPumpSession: Cannot connect to the pump. Abandoning")
                        return
                    mt.beginEHSM()
                    try:    
                        # We need to read always the pump time to store the offset for later messeging
                        mt.getPumpTime()
                        try:
                            downloadOperations(mt)
                        except Exception:
                            logger.error("Unexpected error in client downloadOperations", exc_info = True)
                            raise
                    finally:
                        mt.finishEHSM()
                finally:
                    mt.closeConnection()
            finally:
                mt.exitPassthroughMode()
        finally:
            mt.exitControlMode()
    finally:
        mt.closeDevice()

def pumpDownload(mt):
    status = mt.getPumpStatus()
    print (binascii.hexlify( status.responsePayload ))
    print ("Active Insulin: {0:.3f}U".format( status.activeInsulin ))
    print ("Sensor BGL: {0} mg/dL ({1:.1f} mmol/L) at {2}".format( status.sensorBGL,
             status.sensorBGL / 18.016,
             status.sensorBGLTimestamp.strftime( "%c" ) ))
    print ("BGL trend: {0}".format( status.trendArrow ))
    print ("Current basal rate: {0:.3f}U".format( status.currentBasalRate ))
    print ("Temp basal rate: {0:.3f}U".format( status.tempBasalRate ))
    print ("Temp basal percentage: {0}%".format( status.tempBasalPercentage ))
    print ("Units remaining: {0:.3f}U".format( status.insulinUnitsRemaining ))
    print ("Battery remaining: {0}%".format( status.batteryLevelPercentage ))
    
    print ("Getting Pump history info")
    start_date = datetime.datetime.now() - datetime.timedelta(days=1)
    historyInfo = mt.getPumpHistoryInfo(start_date, datetime.datetime.max, HISTORY_DATA_TYPE.PUMP_DATA)
    # print (binascii.hexlify( historyInfo.responsePayload,  ))
    print (" Pump Start: {0}".format(historyInfo.datetimeStart))
    print (" Pump End: {0}".format(historyInfo.datetimeEnd));
    print (" Pump Size: {0}".format(historyInfo.historySize));
    
    print ("Getting Pump history")
    history_pages = mt.getPumpHistory(historyInfo.historySize, start_date, datetime.datetime.max, HISTORY_DATA_TYPE.PUMP_DATA)

    # Uncomment to save events for testing without Pump (use: tests/process_saved_history.py)
    #with open('history_data.dat', 'wb') as output:
    #    pickle.dump(history_pages, output)

    events = mt.processPumpHistory(history_pages, HISTORY_DATA_TYPE.PUMP_DATA)
    print ("# All Pump events:")
    for ev in events:
        print (" Pump: ", ev)
    print ("# End Pump events")

    print ("Getting sensor history info")
    sensHistoryInfo = mt.getPumpHistoryInfo(start_date, datetime.datetime.max, HISTORY_DATA_TYPE.SENSOR_DATA)
    # print (binascii.hexlify( historyInfo.responsePayload,  ))
    print (" Sensor Start: {0}".format(sensHistoryInfo.datetimeStart))
    print (" Sensor End: {0}".format(sensHistoryInfo.datetimeEnd));
    print (" Sensor Size: {0}".format(sensHistoryInfo.historySize));
    
    print ("Getting Sensor history")
    sensor_history_pages = mt.getPumpHistory(sensHistoryInfo.historySize, start_date, datetime.datetime.max, HISTORY_DATA_TYPE.SENSOR_DATA)

    # Uncomment to save events for testing without Pump (use: tests/process_saved_history.py)
    #with open('sensor_history_data.dat', 'wb') as output:
    #    pickle.dump(sensor_history_pages, output)

    sensorEvents = mt.processPumpHistory(sensor_history_pages, HISTORY_DATA_TYPE.SENSOR_DATA)
    print ("# All Sensor events:")
    for ev in sensorEvents:
        print (" Sensor", ev)
    print ("# End Sensor events")

    
    # print (binascii.hexlify( mt.doRemoteSuspend().responsePayload ))

# Commented code to try remote bolusing...
#    print (binascii.hexlify( mt.do405Message( pumpDatetime.encodedDatetime ).responsePayload ))
#    print (binascii.hexlify( mt.do124Message( pumpDatetime.encodedDatetime ).responsePayload ))
#    print (binascii.hexlify( mt.getBasicParameters().responsePayload ))
#    print (binascii.hexlify( mt.getTempBasalStatus().responsePayload ))
#    print (binascii.hexlify( mt.getBolusesStatus().responsePayload ))
#    print (binascii.hexlify( mt.doRemoteBolus( 1, 0.1, 0 ).responsePayload ))
#    print (binascii.hexlify( mt.doRemoteBolus( 1, 0.1, 1 ).responsePayload ))
    

if __name__ == '__main__':
    downloadPumpSession(pumpDownload)
