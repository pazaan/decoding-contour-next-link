#!/usr/bin/env python

import sys
import binascii
import pyshark # pip install pyshark
from bitstring import BitArray, BitStream # pip install bigstring
import crc16 # pip install crc16

INCOMING_ENDPOINT = 0x83 # This is the incoming endpoint we want data from
OUTGOING_ENDPOINT = 0x04 # This is the outgoing endpoint we want data from
USB_PACKET_SIZE = 60

class medtronicMessage( object ):
    def __init__( self, stream ):
        self.magicHeader = stream.readlist( '2*bytes:1' )
        if( ord(self.magicHeader[1]) != 0x03 ):
            return

        self.pumpId = stream.read( 'bytes:6' )
        self.unknownBytes = stream.read( 'int:80' ) # This is 80 bits of data
        # If unknownBytes is ever anything other than padded nulls, we want to know about it!
        self.checkNullBytes( 'unknownBytes' )

        self.commandType = stream.read( 'uint:8' )
        self.sequenceNumber = stream.read( 'uintle:32' ) # Assuming for now it's a regular int

        self.unknownBytes2 = stream.read( 'int:40' ) # This is 80 bits of data
        # If unknownBytes is ever anything other than padded nulls, we want to know about it!
        self.checkNullBytes( 'unknownBytes2' )

        self.messageSize = stream.read( 'uintle:32' ) # Assuming for now it's a regular int
        expectedMessageSize = stream.bytepos + self.messageSize + 1 # + 1 because bytepos is an index
        if( ( stream.length / 8 ) != expectedMessageSize ):
            print "Message size mismatch. Expecting message to be '%d' bytes, this stream has '%d' bytes" % ( expectedMessageSize, ( stream.length / 8 ) )
            raise Exception

        self.rollingChecksum = stream.read( 'uintle:8' )

        if( self.messageSize > 0 ):
            self.innerMessage = stream.readlist( 'bytes:s, uintle:16', s = ( self.messageSize - 2 ) )
            calcCcitt = self.ccitt( self.innerMessage[0] )
            if( calcCcitt != self.innerMessage[1] ):
                print "CRC-CCITT doesn't match. Expected '%#x', calculated '%#x'" % ( self.innerMessage[1], calcCcitt )
                # TODO - 0x10 OUT and 0x14 IN command messages don't seem to have the CRC-CCITT. Look into this
                if( self.commandType != 0x10 and self.commandType != 0x14 ):
                    raise Exception

        # Check the rolling Checksum
        calcCrc = self.messageCrc( stream )
        if( calcCrc != self.rollingChecksum ):
            print "Rolling checksum doesn't match. Expected '%#x', calculated '%#x'" % ( self.rollingChecksum, calcCrc )
            raise Exception

    def checkNullBytes( self, field ):
        if( getattr( self, field ) != 0 ):
            print '*** SOMETHING NEW! %s is more than it seems' % ( field )
            raise Exception

    def messageCrc( self, stream ):
        # unpack is the same as readlist, but starts from the beginning of the stream
        bytes = stream.unpack( '%s*uint:8' % ( stream.length / 8 ) )
        # The 33rd byte is the checksum itself, and shouldn't be included in the rolling checksum
        del bytes[32]
        return sum(bytes) & 0xff

    def ccitt( self, bytes ):
        crc = crc16.crc16xmodem( bytes, 0xffff )
        return crc & 0xffff

    def __str__( self ):
        if( ord(self.magicHeader[1]) != 0x03 ):
            return 'Not a Medtronic long message'

        return '%s, %s, %s, %#x, %d, %#x, %d, %#x\n%s' % ( self.magicHeader, self.pumpId, self.unknownBytes, self.commandType, self.sequenceNumber, self.unknownBytes2, self.messageSize, self.rollingChecksum, self.innerMessage[0].encode('hex') if hasattr( self, 'innerMessage' ) else '' )

cap = pyshark.FileCapture( sys.argv[1] )

messageBuffer = BitStream()

i = 0

for packet in cap:
    # Make sure the data is coming from one of the USB endpoints we care about.
    # Skip anything else
    usbEndpoint = int( packet.usb.endpoint_number, 16 )

    if( usbEndpoint != INCOMING_ENDPOINT and
        usbEndpoint != OUTGOING_ENDPOINT ):
        continue

    usbBuffer = BitStream('0x%s' % ( packet.data.usb_capdata.replace( ':', '' ) ) )
    usbHeader = usbBuffer.readlist( 'bytes:3, uint:8' )

    # Validate the header
    if( usbEndpoint == OUTGOING_ENDPOINT and usbHeader[0].encode( 'hex' ) != '000000' ):
        print 'Unexpected USB Header. Expected "0x000000", got "0x%s".' % ( usbHeader[0].encode( 'hex' ) )
        raise Exception
    if( usbEndpoint == INCOMING_ENDPOINT and usbHeader[0] != 'ABC' ):
        print 'Unexpected USB Header. Expected "0x414243", got "0x%s".' % ( usbHeader[0].encode( 'hex' ) )
        raise Exception

    messageBuffer.append( usbBuffer.read( usbHeader[1] * 8 ) )

    # Clear the messageBuffer if we have a full message
    # TODO - we need to be able to figure out if all 60 bytes are conusumed, but it's the end of the message
    if( usbHeader[1] < USB_PACKET_SIZE ):
        print 'Message %s' % ( 'OUT' if usbEndpoint == OUTGOING_ENDPOINT else 'IN' )
        print 'Hex: %s' % ( messageBuffer.hex )
        # If we're up to the non-ASTM messages, let's not bother with the String output
        if( messageBuffer.bytes[0] != 'Q' ):
            print 'String: %s\n' % ( messageBuffer.bytes )
        else:
            msg = medtronicMessage( messageBuffer )
            print msg
            print

        messageBuffer.clear()
        i+=1

print "Processed %d messages" % ( i )
