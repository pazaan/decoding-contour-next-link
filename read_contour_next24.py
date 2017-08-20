#!/usr/bin/env python

# pip install hidapi # Platform independant
import hid
# pip install astm
import astm
import time
import struct
import pprint

#for d in hid.enumerate():
#    keys = d.keys()
#    keys.sort()
#    for key in keys:
#        print "%s : %s" % (key, d[key])
#    print ""

try:
    print "Opening device"
    h = hid.device()
    h.open(0x1a79, 0x6210)
    #h.open(0x1a79, 0x6300)

    print "Manufacturer: %s" % h.get_manufacturer_string()
    print "Product: %s" % h.get_product_string()
    print "Serial No: %s" % h.get_serial_number_string()

    # try writing some data to the device
    #msg = struct.pack('>BBBBB', 0x42, 0x42, 0x43, 1, 0x58) # Send an "X" to start ping the meter?
    msg = struct.pack('>BBBBB', 0x42, 0x42, 0x43, 1, 0x06)
    print ' '.join([hex(ord(x)) for x in msg])

    print "REQUEST LENGTH: " + str( len( msg ) )

    BLOCKSIZE = 64

    while True:
        payload = bytearray()
        h.write(bytearray(msg))
        while True:
            data = h.read(BLOCKSIZE)
            if data:
                # If it comes back with anything else at the front instead of a 0x02 (STX),
                # Then it's a control character that we should handle (eg NAK, ACK, EOT, ENQ)
                #print ' '.join([hex(x) for x in data])
                #print
                if(str(bytearray(data[0:3])) != "ABC" ):
                    print "*** INVALID FRAME"
                payload.extend(data[4:data[3]+4])
                if data[3] != BLOCKSIZE - 4:
                    break

        # Strip the non-printable ASTM characters before showing the Debug string
        print "\nRESPONSE: '" + payload[:-6] + "'"
        # Debug hex output (keep all ASTM characters)
        print "HEX >>>"
        print ' '.join([hex(x) for x in payload])
        print "<<<"
        print "PAYLOAD LENGTH: " + str(len(payload))

        if payload[0] == 0x04:
            print "### Meter sent EOT. We're done"
            break

        print "\n### Time to decode:"
        print astm.codec.is_chunked_message(payload)
        # These need to be put into an array
        # If we don't get a Message Terminator Record, we need to ignore
        # all data that the stick sent.
        dataObject = astm.codec.decode( str(payload) )
        pprint.pprint( dataObject )

        # If this is the Message Terminator Record, then we're done
        if dataObject[0][0] == "L":
            print "### Got Message Terminator Record"
            # Send an EOT?
            #h.write([ 0x06 ])

    print "Closing device"
    h.close()

except IOError, ex:
    print ex
    print "You probably don't have the hard coded test hid. Update the hid.device line"
    print "in this script with one from the enumeration list output above and try again."

print "Done"
