import datetime
from dateutil import tz

class DateTimeHelper( object ):
    # Base time is midnight 1st Jan 2000 (UTC)
    baseTime = 946684800;
    epoch = datetime.datetime.utcfromtimestamp(0)
    
    @staticmethod
    def decodeDateTimeOffset( pumpDateTime ):
        return ( pumpDateTime & 0xffffffff ) - 0x100000000
        
    @staticmethod
    def decodeDateTime( pumpDateTime, offset = None):
        rtc = None
        if offset == None:        
            rtc = ( pumpDateTime >> 32 ) & 0xffffffff
            offset = DateTimeHelper.decodeDateTimeOffset(pumpDateTime)
        else:
            rtc = pumpDateTime

        # The time from the pump represents epochTime in UTC, but we treat it as if it were in our own timezone
        # We do this, because the pump does not have a concept of timezone
        # For example, if baseTime + rtc + offset was 1463137668, this would be
        # Fri, 13 May 2016 21:07:48 UTC.
        # However, the time the pump *means* is Fri, 13 May 2016 21:07:48 in our own timezone
        offsetFromUTC = (datetime.datetime.utcnow() - datetime.datetime.now()).total_seconds()
        epochTime = DateTimeHelper.baseTime + rtc + offset + offsetFromUTC
        if epochTime < 0:
            epochTime = 0

        #print ' ### DateTimeHelper.decodeDateTime rtc:0x{0:x} {0} offset:0x{1:x} {1} epochTime:0x{2:x} {2}'.format(rtc, offset, epochTime)                    

        # Return a non-naive datetime in the local timezone
        # (so that we can convert to UTC for Nightscout later)
        localTz = tz.tzlocal()
        result = datetime.datetime.fromtimestamp( epochTime, localTz )
        #print ' ### DateTimeHelper.decodeDateTime {0:x} {1}'.format(pumpDateTime, result)        
        return result

    @staticmethod
    def rtcFromDate(userDate, offset):
        epochTime = int((userDate - DateTimeHelper.epoch).total_seconds())
        rtc = epochTime - offset - DateTimeHelper.baseTime;  
        if rtc > 0xFFFFFFFF:
            rtc = 0xFFFFFFFF
        #print ' ### DateTimeHelper.rtcFromDate rtc:0x{0:x} {0} offset:0x{1:x} {1} epochTime:0x{2:x} {2}'.format(rtc, offset, epochTime)                    
        return rtc
