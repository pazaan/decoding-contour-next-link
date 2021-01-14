# decoding-contour-next-link

[![Join the chat at https://gitter.im/pazaan/decoding-contour-next-link](https://badges.gitter.im/pazaan/decoding-contour-next-link.svg)](https://gitter.im/pazaan/decoding-contour-next-link?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Space to collaborate on decoding Contour Next Link 2.4 comms protocols, and the piggy-backed pump comms

## Getting Started
* Make sure you have the following dependencies installed:  
    * `python`
    * `pip`
    * `python-dev`
    * `libusb-1.0-0-dev`
    * `libudev-dev`
    * `liblzo2-dev`

* Clone this project
* If you're running macOS (El Capitan or later), you'll need to update `setuptools` like this first (due to [System Integrity Protection](https://support.apple.com/en-au/HT204899)):
```
$ sudo -H pip install --upgrade setuptools --user python
```
* Install the dependencies:  
```
$ sudo -H pip install cython
$ sudo -H pip install hidapi
$ sudo -H pip install requests astm PyCrypto crc16 python-dateutil
$ sudo -H pip install python-lzo
```
* Plug in your Contour NextLink 2.4 USB stick

Now you can try the script by calling the module from the parent directory
```
$ python -m decoding-contour-next-link.read_minimed_next24
Active Insulin: 0.000U
Sensor BGL: 0 mg/dL (0.0 mmol/L) at Thu Jan  1 01:00:00 1970
BGL trend: 3 arrows down
Current basal rate: 0.600U
Temp basal rate: 0.000U
Temp basal percentage: 0%
Units remaining: 164.000U
Battery remaining: 50%
Getting Pump history info
 Pump Start: 2017-10-24 23:59:59.999972+02:00
 Pump End: 2017-10-26 22:13:21.999983+02:00
 Pump Size: 6144
Getting Pump history
# All Pump events:
(' Pump: ', BolusWizardEstimateEvent 3d 2017-10-24 19:58:44.999969+02:00 BG Input:0, Carbs:3.0, Carb ratio: 0.5, Food est.:1.5, Correction est.:0.0, Wizard est.: 1.5, User modif.: False, Final est.: 1.5, )

[...]

# End Pump events
Getting sensor history info
 Sensor Start: 2017-10-24 23:59:59.999975+02:00
 Sensor End: 2017-10-26 22:13:22.999987+02:00
 Sensor Size: 2048
Getting Sensor history
# All Sensor events:
(' Sensor', NGPHistoryEvent 8 2008-12-31 23:00:10.999966+01:00)
(' Sensor', NGPHistoryEvent 7 2017-08-03 17:19:22.999980+02:00)

[...]

# End Sensor events
```

## Known Issues
* Assumed pump time was in UTC, but this doesn't ring true for non DST times (in Melbourne, anyway)
