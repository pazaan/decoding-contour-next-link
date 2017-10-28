import pickle
import read_minimed_next24
from read_minimed_next24 import HISTORY_DATA_TYPE

if __name__ == '__main__':
    history_pages = None
    with open('testdata/paulokow_20170827_sample.dat', 'rb') as input_file:
        history_pages = pickle.load(input_file)
    history_pages2 = []
    for l in history_pages:
        grp = []
        for it in l:
            grp.append(bytes(it))
        history_pages2.append(grp)    
#    with open('testdata/paulokow_20170827_sample2.dat', 'wb') as output_file:
#        pickle.dump(history_pages2, output_file)

    mt = read_minimed_next24.Medtronic600SeriesDriver()
    events = mt.processPumpHistory(history_pages2, HISTORY_DATA_TYPE.PUMP_DATA)
    print ("# All events:")
    for ev in events:
        print (ev)
    print ("# End events")
