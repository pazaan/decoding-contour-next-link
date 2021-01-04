#!/usr/bin/env python

import requests # pip install requests
import binascii
import javaobj
import io
import struct
import sys
import getpass
import argparse
import logging # To make javaobj's logger be quiet
import sqlite3
import re
import hashlib

logging.disable( logging.CRITICAL )

from read_minimed_next24 import Config, Medtronic600SeriesDriver

class CareLinkRequest( javaobj.JavaObjectMarshaller ):
    def __init__( self, minimedAddressRoot ):
        self.object_stream = io.BytesIO()
        self._writeStreamHeader()
        self.minimedAddressRoot = minimedAddressRoot

class CareLinkKeyRequest( CareLinkRequest ):
    def buildRequest( self, serial ):
        self.writeObject( struct.pack( '>I', 0x1f ) )
        self.write_string( serial )
        return self.object_stream.getvalue()

    def decodeResponse( self, data ):
        decoder = javaobj.JavaObjectUnmarshaller( io.BytesIO(data) )
        int1 = struct.unpack( '>I', decoder.readObject() )[0]
        # If int1 is 16, then we have valid data in the following object. If it's 0,
        # then no data follows
        print "INT RESPONSE: {0}".format( int1 )
        if int1 > 0:
            keyArray = decoder.readObject()
            key = ''.join('{:02x}'.format( x & 0xff ) for x in keyArray )
            count = struct.unpack( '>I', decoder.readObject() )[0]
            print "COUNT: {0}".format( count )
        else:
            key = None
            count = 0
        return ( int1, key, count )

    def post( self, longSerial, session ):
        data = self.buildRequest( longSerial )

        response = session.post( 'https://%s/patient/main/../secure/SnapshotServer/' % self.minimedAddressRoot,
            headers = { 'Content-Type': 'application/octet-stream' },
            data = data
        )

        print "Status code: {0}".format( response.status_code )
        print binascii.hexlify( response.content )
        return self.decodeResponse( response.content )

class CareLinkHMACRequest( CareLinkRequest ):
    def buildRequest( self, serial ):
        self.writeObject( struct.pack( '>I', 0x1c ) )
        self.write_string( serial )
        return self.object_stream.getvalue()

    def decodeResponse( self, data ):
        decoder = javaobj.JavaObjectUnmarshaller( io.BytesIO(data ) )
        hmacArray = decoder.readObject()
        hmac = ''.join('{:02x}'.format( x & 0xff ) for x in reversed(hmacArray) )
        return hmac

    def post( self, serial, session ):
        data = self.buildRequest( serial )

        response = session.post( 'https://%s/patient/main/../secure/SnapshotServer/' % self.minimedAddressRoot,
            headers = { 'Content-Type': 'application/octet-stream' },
            data = data
        )

        return self.decodeResponse( response.content )

def getHmac( serial ):
    paddingKey = "A4BD6CED9A42602564F413123"
    digest = hashlib.sha256(serial + paddingKey).hexdigest()
    return "".join(reversed([digest[i:i+2] for i in range(0, len(digest), 2)]))

def getHmacAndKey( config, serial, longSerial, session, addressRoot ):
    #request = CareLinkHMACRequest(addressRoot)
    #hmac = request.post( serial, session )
    hmac = getHmac( serial )

    request = CareLinkKeyRequest(addressRoot)
    ( int1, key, count ) = request.post( longSerial, session )

    config.hmac = hmac
    config.key = key
    print( 'HMAC for serial {0}: {1}'.format( serial, hmac ) )
    print( 'KEY for serial {0}: {1}'.format( serial, key ) )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument( 'username', help='The CareLink username with which to retrieve the HMAC and key' )
    parser.add_argument( '--db', action='store_true', help='Process all entries in the config database, rather than the connected USB stick' )
    parser.add_argument( '-a', '--addressRoot', type=str, default='carelink.minimed.eu', help='The domain name of which CareLink reagion you wish to connect to.  Defaults to the EU reagion')
    args = parser.parse_args()

    password = getpass.getpass( 'Enter the password for the CareLink user {0}: '.format( args.username ) )

    if args.db:
        conn = sqlite3.connect( 'read_minimed.db' )
        c = conn.cursor()

        c.execute( 'SELECT * FROM config' )

    payload = {
        'j_username': args.username,
        'j_password': password,
        'j_character_encoding': 'UTF-8'
    }

    with requests.Session() as session:
        session.post( 'https://%s/patient/j_security_check' % args.addressRoot, data = payload )

        if args.db:
            for row in c.fetchall():
                # set up the sqlite3 database if required...
                longSerial = str( row[0] )
                serial = str( re.sub( r"\d+-", "", longSerial ) )
                config = Config( longSerial )

                getHmacAndKey( config, serial, longSerial, session )
        else:
            try:
                mt = Medtronic600SeriesDriver()
                mt.openDevice()
                mt.getDeviceInfo()

                print (mt.deviceSerial)
                if mt.deviceSerial == None:
                    raise Exception()
            except Exception:
                print ("Please plug in your Contour NextLink 2.4, and rerun this script")
                sys.exit( 1 )

            longSerial = str( mt.deviceSerial )
            serial = re.sub( r"\d+-", "", longSerial )
            config = Config( longSerial )

            getHmacAndKey( config, serial, longSerial, session, args.addressRoot )
