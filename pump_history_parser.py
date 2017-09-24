from helpers import DateTimeHelper, NumberHelper
import struct
import binascii
from datetime import timedelta

class NGPHistoryEvent:
    class EVENT_TYPE:
        TIME_RESET = 0x02
        USER_TIME_DATE_CHANGE = 0x03
        SOURCE_ID_CONFIGURATION = 0x04
        NETWORK_DEVICE_CONNECTION = 0x05
        AIRPLANE_MODE = 0x06
        START_OF_DAY_MARKER = 0x07
        END_OF_DAY_MARKER = 0x08
        PLGM_CONTROLLER_STATE = 0x0B
        CLOSED_LOOP_STATUS_DATA = 0x0C
        CLOSED_LOOP_PERIODIC_DATA = 0x0D
        CLOSED_LOOP_DAILY_DATA = 0x0E
        NORMAL_BOLUS_PROGRAMMED = 0x15
        SQUARE_BOLUS_PROGRAMMED = 0x16
        DUAL_BOLUS_PROGRAMMED = 0x17
        CANNULA_FILL_DELIVERED = 0x1A
        TEMP_BASAL_PROGRAMMED = 0x1B
        BASAL_PATTERN_SELECTED = 0x1C
        BASAL_SEGMENT_START = 0x1D
        INSULIN_DELIVERY_STOPPED = 0x1E
        INSULIN_DELIVERY_RESTARTED = 0x1F
        SELF_TEST_REQUESTED = 0x20
        SELF_TEST_RESULTS = 0x21
        TEMP_BASAL_COMPLETE = 0x22
        BOLUS_SUSPENDED = 0x24
        SUSPENDED_BOLUS_RESUMED = 0x25
        SUSPENDED_BOLUS_CANCELED = 0x26
        BOLUS_CANCELED = 0x27
        ALARM_NOTIFICATION = 0x28
        ALARM_CLEARED = 0x2A
        LOW_RESERVOIR = 0x2B
        BATTERY_INSERTED = 0x2C
        FOOD_EVENT_MARKER = 0x2E
        EXERCISE_EVENT_MARKER = 0x2F
        INJECTION_EVENT_MARKER = 0x30
        OTHER_EVENT_MARKER = 0x31
        BG_READING = 0x32
        CODE_UPDATE = 0x33
        MISSED_MEAL_BOLUS_REMINDER_EXPIRED = 0x34
        REWIND = 0x36
        BATTERY_REMOVED = 0x37
        CALIBRATION_COMPLETE = 0x38
        ACTIVE_INSULIN_CLEARED = 0x39
        DAILY_TOTALS = 0x3C
        BOLUS_WIZARD_ESTIMATE = 0x3D
        MEAL_WIZARD_ESTIMATE = 0x3E
        CLOSED_LOOP_DAILY_TOTALS = 0x3F
        USER_SETTINGS_SAVE = 0x50
        USER_SETTINGS_RESET_TO_DEFAULTS = 0x51
        OLD_BASAL_PATTERN = 0x52
        NEW_BASAL_PATTERN = 0x53
        OLD_PRESET_TEMP_BASAL = 0x54
        NEW_PRESET_TEMP_BASAL = 0x55
        OLD_PRESET_BOLUS = 0x56
        NEW_PRESET_BOLUS = 0x57
        MAX_BASAL_RATE_CHANGE = 0x58
        MAX_BOLUS_CHANGE = 0x59
        PERSONAL_REMINDER_CHANGE = 0x5A
        MISSED_MEAL_BOLUS_REMINDER_CHANGE = 0x5B
        BOLUS_INCREMENT_CHANGE = 0x5C
        BOLUS_WIZARD_SETTINGS_CHANGE = 0x5D
        OLD_BOLUS_WIZARD_INSULIN_SENSITIVITY = 0x5E
        NEW_BOLUS_WIZARD_INSULIN_SENSITIVITY = 0x5F
        OLD_BOLUS_WIZARD_INSULIN_TO_CARB_RATIOS = 0x60
        NEW_BOLUS_WIZARD_INSULIN_TO_CARB_RATIOS = 0x61
        OLD_BOLUS_WIZARD_BG_TARGETS = 0x62
        NEW_BOLUS_WIZARD_BG_TARGETS = 0x63
        DUAL_BOLUS_OPTION_CHANGE = 0x64
        SQUARE_BOLUS_OPTION_CHANGE = 0x65
        EASY_BOLUS_OPTION_CHANGE = 0x66
        BG_REMINDER_OPTION_CHANGE = 0x68
        BG_REMINDER_TIME = 0x69
        AUDIO_VIBRATE_MODE_CHANGE = 0x6A
        TIME_FORMAT_CHANGE = 0x6B
        LOW_RESERVOIR_WARNING_CHANGE = 0x6C
        LANGUAGE_CHANGE = 0x6D
        STARTUP_WIZARD_START_END = 0x6E
        REMOTE_BOLUS_OPTION_CHANGE = 0x6F
        AUTO_SUSPEND_CHANGE = 0x72
        BOLUS_DELIVERY_RATE_CHANGE = 0x73
        DISPLAY_OPTION_CHANGE = 0x77
        SET_CHANGE_REMINDER_CHANGE = 0x78
        BLOCK_MODE_CHANGE = 0x79
        BOLUS_WIZARD_SETTINGS_SUMMARY = 0x7B
        CLOSED_LOOP_BG_READING = 0x82
        CLOSED_LOOP_OPTION_CHANGE = 0x86
        CLOSED_LOOP_SETTINGS_CHANGED = 0x87
        CLOSED_LOOP_TEMP_TARGET_STARTED = 0x88
        CLOSED_LOOP_TEMP_TARGET_ENDED = 0x89
        CLOSED_LOOP_ALARM_AUTO_CLEARED = 0x8A
        SENSOR_SETTINGS_CHANGE = 0xC8
        OLD_SENSOR_WARNING_LEVELS = 0xC9
        NEW_SENSOR_WARNING_LEVELS = 0xCA
        GENERAL_SENSOR_SETTINGS_CHANGE = 0xCB
        SENSOR_GLUCOSE_READINGS = 0xCC
        SENSOR_GLUCOSE_GAP = 0xCD
        GLUCOSE_SENSOR_CHANGE = 0xCE
        SENSOR_CALIBRATION_REJECTED = 0xCF
        SENSOR_ALERT_SILENCE_STARTED = 0xD0
        SENSOR_ALERT_SILENCE_ENDED = 0xD1
        OLD_LOW_SENSOR_WARNING_LEVELS = 0xD2
        NEW_LOW_SENSOR_WARNING_LEVELS = 0xD3
        OLD_HIGH_SENSOR_WARNING_LEVELS = 0xD4
        NEW_HIGH_SENSOR_WARNING_LEVELS = 0xD5
        SENSOR_GLUCOSE_READINGS_EXTENDED = 0xD6
        NORMAL_BOLUS_DELIVERED = 0xDC
        SQUARE_BOLUS_DELIVERED = 0xDD
        DUAL_BOLUS_PART_DELIVERED = 0xDE
        CLOSED_LOOP_TRANSITION = 0xDF
        GENERATED__SENSOR_GLUCOSE_READINGS_EXTENDED_ITEM = 0xD601 #this is not a pump event, it's generated from single items within SENSOR_GLUCOSE_READINGS_EXTENDED 

    def __init__(self, eventData):
        self.eventData = eventData;

    @property
    def source(self):
        # No idea what "source" means.
        return struct.unpack( '>B', self.eventData[1:2] )[0] # self.eventData[0x01];

    @property
    def size(self):
        return struct.unpack( '>B', self.eventData[2:3] )[0]#this.eventData[0x02];

    @property
    def eventType(self):
        return struct.unpack( '>B', self.eventData[0:1] )[0]#this.eventData[0];

    @property
    def timestamp(self):
        return DateTimeHelper.decodeDateTime( struct.unpack( '>Q', self.eventData[3:11] )[0] )

    @property
    def dynamicActionRequestor(self):
        return struct.unpack( '>B', self.eventData[1:2] )[0] # self.eventData[0x01];
    
    def __str__(self):
        return '{0} {1:x} {2}'.format(self.__class__.__name__, self.eventType, self.timestamp)
    
    def allNestedEvents(self):
        yield self.eventInstance()
    
    def eventInstance(self):
        if self.eventType == NGPHistoryEvent.EVENT_TYPE.BG_READING:
            return BloodGlucoseReadingEvent(self.eventData)
        elif self.eventType == NGPHistoryEvent.EVENT_TYPE.NORMAL_BOLUS_DELIVERED:            
            return NormalBolusDeliveredEvent(self.eventData);
        elif self.eventType == NGPHistoryEvent.EVENT_TYPE.SENSOR_GLUCOSE_READINGS_EXTENDED:            
            return SensorGlucoseReadingsEvent(self.eventData);
        return self
#       case NGPHistoryEvent.EVENT_TYPE.OLD_BOLUS_WIZARD_BG_TARGETS:
#         return new OldBolusWizardBgTargetsEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.NEW_BOLUS_WIZARD_BG_TARGETS:
#         return new NewBolusWizardBgTargetsEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.OLD_BOLUS_WIZARD_INSULIN_SENSITIVITY:
#         return new OldBolusWizardInsulinSensitivityEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.NEW_BOLUS_WIZARD_INSULIN_SENSITIVITY:
#         return new NewBolusWizardInsulinSensitivityEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.OLD_BOLUS_WIZARD_INSULIN_TO_CARB_RATIOS:
#         return new OldBolusWizardCarbsRatiosEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.NEW_BOLUS_WIZARD_INSULIN_TO_CARB_RATIOS:
#         return new NewBolusWizardCarbsRatiosEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.BOLUS_WIZARD_SETTINGS_SUMMARY:
#         return this;
#       case NGPHistoryEvent.EVENT_TYPE.OLD_BASAL_PATTERN:
#         return new OldBasalPatternEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.NEW_BASAL_PATTERN:
#         return new NewBasalPatternEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.BASAL_PATTERN_SELECTED:
#         return new BasalPatternSelectedEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.USER_TIME_DATE_CHANGE:
#         return new UserTimeDateEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.LOW_RESERVOIR:
#         return new LowReservoirEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.BG_READING:
#         return new BloodGlucoseReadingEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.CLOSED_LOOP_BG_READING:
#         return new ClosedLoopBloodGlucoseReadingEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.BASAL_SEGMENT_START:
#         return new BasalSegmentStartEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.TEMP_BASAL_COMPLETE:
#         return new TempBasalCompleteEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.REWIND:
#         return new RewindEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.CANNULA_FILL_DELIVERED:
#         return new CannulaFillDeliveredEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.SQUARE_BOLUS_DELIVERED:
#         return new SquareBolusDeliveredEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.DUAL_BOLUS_PART_DELIVERED:
#         return new DualBolusPartDeliveredEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.BOLUS_WIZARD_ESTIMATE:
#         return new BolusWizardEstimateEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.INSULIN_DELIVERY_STOPPED:
#         return new InsulinDeliveryStoppedEvent(this.eventData);
#       case NGPHistoryEvent.EVENT_TYPE.INSULIN_DELIVERY_RESTARTED:
#         return new InsulinDeliveryRestartedEvent(this.eventData);
#       default:
#         // Return a default NGPHistoryEvent
#         return this;
#     }

class BloodGlucoseReadingEvent(NGPHistoryEvent):
    def __init__(self, eventData):
        NGPHistoryEvent.__init__(self, eventData)
        
    def __str__(self):
        return '{0} {1}'.format(NGPHistoryEvent.__str__(self), self.bgValue)


#    @property
#    def meterSerialNumber(self):
#     return this.eventData.slice(0x0F, this.eventData.length).toString().replace(' ', '').split('')
#       .reverse()
#       .join('');

#   See NGPUtil.NGPConstants.BG_SOURCE
#   get bgSource() {
#     return this.eventData[0x0E];
#   }

    @property
    def bgValue(self):
        # bgValue is always in mg/dL.
        return struct.unpack( '>H', self.eventData[12:14] )[0]#this.eventData.readUInt16BE(0x0C);

#   get bgUnits() {
#     // bgValue is always in mg/dL. bgUnits tells us which units the device is set in.
#     // eslint-disable-next-line no-bitwise
#     return this.eventData[0x0B] & 1 ?
#       NGPUtil.NGPConstants.BG_UNITS.MG_DL :
#       NGPUtil.NGPConstants.BG_UNITS.MMOL_L;
#   }
# 
#   get calibrationFlag() {
#     // eslint-disable-next-line no-bitwise
#     return (this.eventData[0x0B] & 2) === 2;
#   }
# 
#   get bgLinked() {
#     return this.meterSerialNumber !== '';
#   }
# 
#   get isCalibration() {
#     return (this.bgSource === NGPUtil.NGPConstants.BG_SOURCE.SENSOR_CAL || this.calibrationFlag);
#   }

class BolusDeliveredEvent(NGPHistoryEvent):
    def __init__(self, eventData):
        NGPHistoryEvent.__init__(self, eventData)
        
    def __str__(self):
        return '{0} Source:{1}, Number:{2}, presetBolusNumber:{3}'.format(NGPHistoryEvent.__str__(self), self.bolusSource, self.bolusNumber, self.presetBolusNumber)

    @property
    def bolusSource(self):
        return struct.unpack( '>B', self.eventData[0x0B:0x0C] )[0]#return this.eventData[0x0B];

    @property
    def bolusNumber(self):
        return struct.unpack( '>B', self.eventData[0x0C:0x0D] )[0]#return this.eventData[0x0C];

    @property
    def presetBolusNumber(self):
        # See NGPUtil.NGPConstants.BOLUS_PRESET_NAME
        return struct.unpack( '>B', self.eventData[0x0D:0x0E] )[0]#return this.eventData[0x0D];
    


class NormalBolusDeliveredEvent(BolusDeliveredEvent):
    def __init__(self, eventData):
        NGPHistoryEvent.__init__(self, eventData)
        
    def __str__(self):
        return '{0} Del:{1}, Prog:{2}, Active:{3}'.format(NGPHistoryEvent.__str__(self), self.deliveredAmount, self.programmedAmount, self.activeInsulin)

    @property
    def deliveredAmount(self):
        return struct.unpack( '>I', self.eventData[0x12:0x16] )[0] / 10000.0 #return this.eventData.readUInt32BE(0x12) / 10000.0;

    @property
    def programmedAmount(self):
        return struct.unpack( '>I', self.eventData[0x0E:0x12] )[0] / 10000.0 #return this.eventData.readUInt32BE(0x12) / 10000.0;

    @property
    def activeInsulin(self):
        return struct.unpack( '>I', self.eventData[0x16:0x1A] )[0] / 10000.0 #return this.eventData.readUInt32BE(0x16) / 10000.0;

class SensorGlucoseReadingsEvent(NGPHistoryEvent):
    def __init__(self, eventData):
        NGPHistoryEvent.__init__(self, eventData)
        
    def __str__(self):
        return '{0}'.format(NGPHistoryEvent.__str__(self))    

    @property
    def minutesBetweenReadings(self):
        return struct.unpack( '>B', self.eventData[0x0B:0x0C] )[0]#return this.eventData[0x0B];

    @property
    def numberOfReadings(self):
        return struct.unpack( '>B', self.eventData[0x0C:0x0D] )[0]#return this.eventData[0x0C];

    @property
    def predictedSg(self):
        return struct.unpack( '>H', self.eventData[0x0D:0x0F] )[0]#return this.eventData.readUInt16BE(0x0D);

    def allNestedEvents(self):
        pos = 15
        for i in range(0, self.numberOfReadings):
            #const timestamp = new NGPUtil.NGPTimestamp(this.timestamp.rtc - (i * this.minutesBetweenReadings * 60), this.timestamp.offset);
            timestamp = self.timestamp + timedelta(minutes = i * self.minutesBetweenReadings)
            payloadDecoded = struct.unpack( '>BBHBhBB', self.eventData[pos:pos + 9] )

            #const sg = ((this.eventData[pos] & 3) << 8) | this.eventData[pos + 1];
            sg = (payloadDecoded[0] & 0x03) << 8 | payloadDecoded[1]            
            #      const vctr = NGPUtil.make32BitIntFromNBitSignedInt((((this.eventData[pos] >> 2) & 3) << 8) | this.eventData[pos + 4], 10) / 100.0;
            # not sure what this value means so cannot say if it's correct
            vctr = NumberHelper.make32BitIntFromNBitSignedInt((((payloadDecoded[0] >> 0x02) & 0x03) << 8) | payloadDecoded[3], 10) / 100.0;
            
            #const isig = this.eventData.readInt16BE(pos + 2) / 100.0;
            isig = payloadDecoded[2] / 100.0;
            #const rateOfChange = this.eventData.readInt16BE(pos + 5) / 100.0;
            rateOfChange = payloadDecoded[4] / 100.0;
            #const readingStatus = this.eventData[pos + 8];
            readingStatus = payloadDecoded[6];
            #const sensorStatus = this.eventData[pos + 7];
            sensorStatus = payloadDecoded[5];
            
            #const backfilledData = (readingStatus & 1) === 1;
            backfilledData = (readingStatus & 0x01) == 0x01
            #const settingsChanged = (readingStatus & 2) === 1; #bug?
            settingsChanged = (readingStatus & 0x02) == 0x02
            #const noisyData = sensorStatus === 1;
            noisyData = sensorStatus == 1
            #const discardData = sensorStatus === 2;
            discardData = sensorStatus == 2
            #const sensorError = sensorStatus === 3;
            sensorError = sensorStatus == 3
            # TODO - handle all the error states where sg >= 769 (see ParseCGM.js)?


            yield SensorGlucoseReading(timestamp = timestamp, 
                                       dynamicActionRequestor = self.dynamicActionRequestor, 
                                       sg = sg,
                                       predictedSg = self.predictedSg,
                                       noisyData = noisyData,
                                       discardData = discardData,
                                       sensorError = sensorError,
                                       backfilledData = backfilledData,
                                       settingsChanged = settingsChanged,
                                       isig = isig,
                                       rateOfChange = rateOfChange,
                                       vctr = vctr)
            pos += 9;


class SensorGlucoseReading(NGPHistoryEvent):
    def __init__(self, 
                 timestamp, 
                 dynamicActionRequestor, 
                 sg, 
                 predictedSg = 0, 
                 isig = 0, 
                 vctr = 0, 
                 rateOfChange = 0, 
                 backfilledData = False,
                 settingsChanged = False,
                 noisyData = False,
                 discardData = False,
                 sensorError = False):
        self.timestamp = timestamp
        self.dynamicActionRequestor = dynamicActionRequestor
        self.sg = sg
        self.predictedSg = predictedSg
        self.isig = isig
        self.vctr = vctr
        self.rateOfChange = rateOfChange
        self.backfilledData = backfilledData
        self.settingsChanged = settingsChanged
        self.noisyData = noisyData
        self.discardData = discardData
        self.sensorError = sensorError
    
    def __str__(self):
        return ("{0} SG:{1}, predictedSg:{2}, "
                "isig:{6}, rateOfChange:{7}, "
                "noisyData:{3}, discardData: {4}, sensorError:{5}").format(
            NGPHistoryEvent.__str__(self), 
            self.sg, 
            self.predictedSg,        
            self.noisyData,
            self.discardData,
            self.sensorError,
            self.isig,
            self.rateOfChange)

    @property
    def source(self):
        # No idea what "source" means.
        return struct.unpack( '>B', self.eventData[1:2] )[0] # self.eventData[0x01];

    @property
    def size(self):
        return 0

    @property
    def eventType(self):
        return NGPHistoryEvent.EVENT_TYPE.GENERATED__SENSOR_GLUCOSE_READINGS_EXTENDED_ITEM

    def eventInstance(self):
        return self