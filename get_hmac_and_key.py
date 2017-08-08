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
logging.disable( logging.CRITICAL )

from read_minimed_next24 import Config, MedtronicMachine

class CareLinkRequest( javaobj.JavaObjectMarshaller ):
    def __init__( self ):
        self.object_stream = io.StringIO()
        self._writeStreamHeader()

class CareLinkKeyRequest( CareLinkRequest ):
    def buildRequest( self, serial ):
        self.writeObject( struct.pack( '>I', 0x1f ) )
        self.write_string( serial )
        return self.object_stream.getvalue()

    def decodeResponse( self, data ):
        decoder = javaobj.JavaObjectUnmarshaller( io.StringIO( data ) )
        int1 = struct.unpack( '>I', decoder.readObject() )[0]
        keyArray = decoder.readObject()
        key = ''.join('{:02x}'.format( x & 0xff ) for x in keyArray )
        count = struct.unpack( '>I', decoder.readObject() )[0]
        return ( int1, key, count )

    def post( self, longSerial, session ):
        data = self.buildRequest( longSerial )

        response = session.post( 'https://carelink.minimed.eu/patient/main/../secure/SnapshotServer/',
            headers = { 'Content-Type': 'application/octet-stream' },
            stream = True,
            data = data
        )

        return self.decodeResponse( response.raw.read() )

class CareLinkHMACRequest( CareLinkRequest ):
    def buildRequest( self, serial ):
        self.writeObject( struct.pack( '>I', 0x1c ) )
        self.write_string( serial )
        return self.object_stream.getvalue()

    def decodeResponse( self, data ):
        decoder = javaobj.JavaObjectUnmarshaller( io.StringIO( data ) )
        hmacArray = decoder.readObject()
        hmac = ''.join('{:02x}'.format( x & 0xff ) for x in reversed(hmacArray) )
        return hmac

    def post( self, serial, session ):
        data = self.buildRequest( serial )

        response = session.post( 'https://carelink.minimed.eu/patient/main/../secure/SnapshotServer/',
            headers = { 'Content-Type': 'application/octet-stream' },
            stream = True,
            data = data
        )

        return self.decodeResponse( response.raw.read() )

def getHmacAndKey( config, serial, longSerial, session ):
    request = CareLinkHMACRequest()
    hmac = request.post( serial, session )

    request = CareLinkKeyRequest()
    ( int1, key, count ) = request.post( longSerial, session )

    config.hmac = hmac
    config.key = key
    print( 'HMAC for serial {0}: {1}'.format( serial, hmac ) )
    print( 'KEY for serial {0}: {1}'.format( serial, key ) )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument( 'username', help='The CareLink username with which to retrieve the HMAC and key' )
    parser.add_argument( '--db', action='store_true', help='Process all entries in the config database, rather than the connected USB stick' )
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
        session.post( 'https://carelink.minimed.eu/patient/j_security_check', data = payload )

        if args.db:
            for row in c.fetchall():
                # set up the sqlite3 database if required...
                longSerial = str( row[0] )
                serial = str( re.sub( r"\d+-", "", longSerial ) )
                config = Config( longSerial )

                getHmacAndKey( config, serial, longSerial, session )
        else:
            try:
                mt = MedtronicMachine()
                mt.initDevice()
                mt.getDeviceInfo()

                if mt.deviceSerial == None:
                    raise Exception()
            except Exception:
                print ("Please plug in your Contour NextLink 2.4, and rerun this script")
                sys.exit( 1 )

            longSerial = str( mt.deviceSerial )
            serial = re.sub( r"\d+-", "", longSerial )
            config = Config( longSerial )

            getHmacAndKey( config, serial, longSerial, session )
