import datetime
from dateutil import tz

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
        if epochTime < 0:
            epochTime = 0

        # Return a non-naive datetime in the local timezone
        # (so that we can convert to UTC for Nightscout later)
        localTz = tz.tzlocal()
        return datetime.datetime.fromtimestamp( epochTime, localTz )
