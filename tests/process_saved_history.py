import pickle
import read_minimed_next24

if __name__ == '__main__':
    history_pages = None
    with open('../testdata/mortlind_20170923_cgm_sample.dat', 'rb') as input_file:
        history_pages = pickle.load(input_file)
    mt = read_minimed_next24.Medtronic600SeriesDriver()
    events = mt.processPumpHistory(history_pages)
    print "# All events:"
    for ev in events:
        print ev
    print "# End events"