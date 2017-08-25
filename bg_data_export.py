#!/usr/bin/env python

import read_minimed_next24
import datetime
from pump_history_parser import NGPHistoryEvent
from pump_history_parser import BloodGlucoseReadingEvent


def historyDownload(mt):
    print "Getting history info"
    historyInfo = mt.getPumpHistoryInfo(datetime.datetime(2017, 8, 23), datetime.datetime.max)
    print "History start {0}".format(historyInfo.datetimeStart)
    print "History end {0}".format(historyInfo.datetimeEnd)
    print "Hisotry size {0}".format(historyInfo.historySize)
    
    print "Getting history"
    history_pages = mt.getPumpHistory(historyInfo.historySize, datetime.datetime(2017, 8, 23), datetime.datetime.max)

    events = mt.processPumpHistory(history_pages)
    print "# All events:"
    for ev in events:
        if isinstance(ev, BloodGlucoseReadingEvent):
            print ev
    print "# End events"

if __name__ == '__main__':
    read_minimed_next24.downloadPumpSession(historyDownload) 
    
