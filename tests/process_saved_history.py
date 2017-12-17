import pickle
import decoding_contour_next_link
from decoding_contour_next_link import HISTORY_DATA_TYPE

if __name__ == '__main__':
    history_pages = None
    with open('../testdata/paulokow_20170827_sample.dat', 'rb') as input_file:
        history_pages = pickle.load(input_file)
    mt = decoding_contour_next_link.Medtronic600SeriesDriver()
    events = mt.processPumpHistory(history_pages, HISTORY_DATA_TYPE.PUMP_DATA)
    print "# All events:"
    for ev in events:
        print ev
    print "# End events"