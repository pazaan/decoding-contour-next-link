#!/usr/bin/env python

import read_minimed_next24
import datetime
from pump_history_parser import NGPHistoryEvent
from pump_history_parser import BloodGlucoseReadingEvent

from datetime import datetime, timedelta
from pymongo import MongoClient

import json


class LatestActivity (object):

    def __init__(self):
        self.db=MongoClient().bg_db
    
    def get_max_bg_record(self):
        pipeline = [
            {
              "$group": {
                "_id": "$item",
                "date": { "$max": "$timestamp"}
              }
            }
          ]
        max_list=list(self.db.bg_valueses.aggregate(pipeline))
        if len(max_list) > 0:
            rec = max_list[0]
            print rec
            return rec["date"]
        else:
            print "Nothing find in DB"
            return datetime.min

    def getConfig(self):
        self.config = self.db.bg_config2.find_one();
        if self.config == None:
            self.config = {
#            "_id": None,
                "lastPumpRead": datetime.min
            }

    def historyDownload(self, mt):
        enddate=datetime.now()
        startdate=self.get_max_bg_record()
        print "Download from {0} to {1}".format(startdate, enddate)

        
        print "Getting history info"
        historyInfo = mt.getPumpHistoryInfo(startdate, enddate)
        print "History start {0}".format(historyInfo.datetimeStart)
        print "History end {0}".format(historyInfo.datetimeEnd)
        print "Hisotry size {0}".format(historyInfo.historySize)
        
        print "Getting history"
        history_pages = mt.getPumpHistory(historyInfo.historySize, startdate, enddate)
    
        events = mt.processPumpHistory(history_pages)
        print "# All events:"
        for ev in events:
            if isinstance(ev, BloodGlucoseReadingEvent):
                print "Writing: ", ev
                to_write = {
                    "timestamp": ev.timestamp,
                    "hour": ev.timestamp.hour,
                    "value": ev.bgValue,
                    "real": True,
                    }
                self.db.bg_valueses.insert_one(to_write)

        #print json.dumps(record, indent=2)
        print "# End events"

        self.config['lastPumpRead'] = datetime.utcnow()
        if u'_id' in self.config:
            self.db.bg_config2.replace_one(filter={u'_id': self.config[u'_id']}, replacement=self.config, upsert=True)
            print 'Config updated', self.config
        else:
            self.db.bg_config2.insert_one(self.config)
            print 'New config saved', self.config

    def init(self):
        self.getConfig()
        print 'Last successful check run:', self.config['lastPumpRead']
        print "Config: ", self.config
        
    def checkIfRun(self):
        dl = datetime.utcnow() - self.config['lastPumpRead']
        if dl.days == 0 and dl.seconds < (60 * 60):
            print 'Short time since last run:', dl
            return False
        else:
            return True
    
    def run(self):
        self.init()
        if (self.checkIfRun()):
            read_minimed_next24.downloadPumpSession(self.historyDownload)

if __name__ == '__main__':
    app = LatestActivity()
    app.run()
