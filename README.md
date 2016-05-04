# decoding-contour-next-link

[![Join the chat at https://gitter.im/pazaan/decoding-contour-next-link](https://badges.gitter.im/pazaan/decoding-contour-next-link.svg)](https://gitter.im/pazaan/decoding-contour-next-link?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Space to collaborate on decoding Contour Next Link comms protocols, and the piggy-backed pump comms

## Getting Started
* Make sure you have `python` and `pip` installed
* Clone this project
* Install the dependencies:
```
$ sudo -H pip install requests hidapi astm transitions PyCrypto crc16
```
* Plug in your Contour NextLink 2.4 USB stick
* Run ```get_hmac_and_key.py``` to get your HMAC and AES key for your USB stick serial number. This script takes one argument, which is your CareLink username. The script will also ask for your password - this is not echoed out or stored at all.
```
$ python get_hmac_and_key.py my_carelink_username  
Enter the password for the CareLink user my_carelink_username:
HMAC for serial 1055866: e28fe4e5cf3c1eb6d6a2ec5a093093d4f397237dc60b3f2c1ef64f31e32077c4
KEY for serial 1055866: 57833334130906a587b7a0437bc28a69
```

Now whenever you run `read_minimed_next24.py`, the script will get the config from the config database and communicate with your pump.
```
$ python read_minimed_next24.py
# Opening device
Manufacturer: Bayer HealthCare LLC
Product: Contour Link USB Device
Serial No: 0000000001055866
# Request Device Info
# Read Device Info
6213-1055866
# Request Open Connection
# Request Read Info
# Negotiate pump comms channel
Negotiating on channel 20
Negotiating on channel 20
Negotiating on channel 17
Negotiating on channel 14
# Begin Extended High Speed Mode Session
# Get Pump Time
Pump time is: Sun, 01 May 2016 16:49:59 +0000
# Get Pump Status
Active Insulin: 0.450U
Sensor BGL: 340 mg/dL (18.9 mmol/L) at Sun, 01 May 2016 16:47:21 +0000
```

## Known Issues
* Assumed pump time was in UTC, but this doesn't ring true for non DST times (in Melbourne, anyway)
* Currently uses `curses.ascii`, which doesn't work on Windows.
