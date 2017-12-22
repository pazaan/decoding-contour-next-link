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
    with open('../testdata/paulokow_20171221_history_640G_with_CGM.dat', 'rb') as input_file:
        history_pages = pickle.load(input_file)
    mt = decoding_contour_next_link.Medtronic600SeriesDriver()
    events = mt.processPumpHistory(history_pages, HISTORY_DATA_TYPE.PUMP_DATA)
    print ("# All events:")
    for ev in events:
        print (ev)
    print ("# End events")
