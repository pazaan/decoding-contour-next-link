import pickle
import decoding_contour_next_link
from decoding_contour_next_link import HISTORY_DATA_TYPE
from datetime import tzinfo, timedelta, datetime

ZERO = timedelta(0)
HOUR = timedelta(hours=1)

# A UTC class.

class UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

utc = UTC()

if __name__ == '__main__':
    history_pages = None
    with open('../testdata/paulokow_20171217_cgm_sample.dat', 'rb') as input_file:
        history_pages = pickle.load(input_file)
    mt = decoding_contour_next_link.Medtronic600SeriesDriver()
    events = mt.processPumpHistory(history_pages, HISTORY_DATA_TYPE.SENSOR_DATA)
    print ("# All events:")
    for ev in events:
        if ev.timestamp > datetime(2017, 12, 14, 19, 0, 0, 0, tzinfo=utc) and ev.timestamp < datetime(2017, 12, 14, 20, 0, 0, 0, tzinfo=utc): 
            print (ev)
    print ("# End events")