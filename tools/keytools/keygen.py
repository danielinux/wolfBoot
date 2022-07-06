#!/usr/bin/python3
'''
 * keygen.py
 *
 * Copyright (C) 2021 wolfSSL Inc.
 *
 * This file is part of wolfBoot.
 *
 * wolfBoot is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfBoot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
'''

import sys,os
from wolfcrypt import ciphers

AUTH_KEY_ED25519 = 0x01
AUTH_KEY_ECC256  = 0x02
AUTH_KEY_RSA2048 = 0x03
AUTH_KEY_RSA4096 = 0x04
AUTH_KEY_ED448   = 0x05
AUTH_KEY_ECC384  = 0x06
AUTH_KEY_ECC521  = 0x07
AUTH_KEY_RSA3072 = 0x08


def usage():
    print("Usage: %s [--ed25519 | --ed448 | --ecc256 | --ecc384 | --ecc521 | --rsa2048| --rsa3072 | --rsa4096] [ --force ] pub_key_file.c\n" % sys.argv[0])
    parser.print_help()
    sys.exit(1)

def dupsign():
    print("")
    print("Error: only one algorithm must be specified.")
    print("")
    usage()

def sign_key_type(name):
    if name == 'ed25519':
        return AUTH_KEY_ED25519
    elif name == 'ed448':
        return AUTH_KEY_ED448
    elif name == 'ecc256':
        return AUTH_KEY_ECC256
    elif name == 'ecc384':
        return AUTH_KEY_ECC384
    elif name == 'ecc521':
        return AUTH_KEY_ECC521
    elif name == 'rsa2048':
        return AUTH_KEY_RSA2048
    elif name == 'rsa3072':
        return AUTH_KEY_RSA3072
    elif name == 'rsa4096':
        return AUTH_KEY_RSA4096
    else:
        return 0

Cfile_Banner="/* Keystore file for wolfBoot, automatically generated. Do not edit.  */\n"+ \
             "/*\n" + \
             " * This file has been generated and contains the public key which is\n"+ \
             " * used by wolfBoot to verify the updates.\n"+ \
             " */" \
             "\n#include <stdint.h>\n#include \"wolfboot/wolfboot.h\"\n\n"


Store_hdr = "struct keystore_slot PubKeys[%d] = {\n"
Slot_hdr  = "\t{\n\t\t.slot_id = %d,\n\t\t.key_type = 0x%02X,\n\t\t.part_id_mask = 0xFFFFFFFF,\n\t\t.pubkey = {\n\t\t\t"
Pubkey_footer = "\n\t\t},"
Slot_footer = "\n\t},"
Store_footer = '\n};\n\n'

sign="ed25519"

import argparse as ap

parser = ap.ArgumentParser(prog='keygen.py', description='wolfBoot key generation tool')
parser.add_argument('--ed25519', dest='ed25519', action='store_true')
parser.add_argument('--ed448', dest='ed448', action='store_true')
parser.add_argument('--ecc256',  dest='ecc256', action='store_true')
parser.add_argument('--ecc384',  dest='ecc384', action='store_true')
parser.add_argument('--ecc521',  dest='ecc521', action='store_true')
parser.add_argument('--rsa2048', dest='rsa2048', action='store_true')
parser.add_argument('--rsa3072', dest='rsa3072', action='store_true')
parser.add_argument('--rsa4096', dest='rsa4096', action='store_true')
parser.add_argument('--force', dest='force', action='store_true')
parser.add_argument('keyfile')

args=parser.parse_args()

#print(args.ecc256)
#sys.exit(0) #test

pubkey_cfile = "src/keystore.c"
key_file = args.keyfile
sign=None
force=False
if (args.ed25519):
    sign='ed25519'
if (args.ed448):
    if sign is not None:
        dupsign()
    sign='ed448'
if (args.ecc256):
    if sign is not None:
        dupsign()
    sign='ecc256'
if (args.ecc384):
    if sign is not None:
        dupsign()
    sign='ecc384'
if (args.ecc521):
    if sign is not None:
        dupsign()
    sign='ecc521'
if (args.rsa2048):
    if sign is not None:
        dupsign()
    sign='rsa2048'
if (args.rsa3072):
    if sign is not None:
        dupsign()
    sign='rsa3072'
if (args.rsa4096):
    if sign is not None:
        dupsign()
    sign='rsa4096'

if sign is None:
    usage()

force = args.force


if pubkey_cfile[-2:] != '.c':
    print("** Warning: generated public key cfile does not have a '.c' extension")


print ("Selected cipher:      " + sign)
print ("Output Private key:   " + key_file)
print ("Output C file:        " + pubkey_cfile)
print()

if (sign == "ed25519"):
    ed = ciphers.Ed25519Private.make_key(32)
    priv,pub = ed.encode_key()
    if os.path.exists(key_file) and not force:
        choice = input("** Warning: key file already exist! Are you sure you want to "+
                "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
        if (choice != "Yes, I am sure!"):
            print("Operation canceled.")
            sys.exit(2)

    print()
    print("Creating file " + key_file)
    with open(key_file, "wb") as f:
        f.write(priv)
        f.write(pub)
        f.close()
    print("Creating file " + pubkey_cfile)
    with open(pubkey_cfile, "w") as f:
        f.write(Cfile_Banner)
        f.write(Store_hdr % 1) # One key
        f.write(Slot_hdr % (0, sign_key_type(sign))) 
        i = 0
        for c in bytes(pub[0:-1]):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n\t\t\t')
        f.write("0x%02X" % pub[-1])
        f.write(Pubkey_footer)
        f.write(Slot_footer)
        f.write(Store_footer)
        f.close()

if (sign == "ed448"):
    ed = ciphers.Ed448Private.make_key(57)
    priv,pub = ed.encode_key()
    if os.path.exists(key_file) and not force:
        choice = input("** Warning: key file already exist! Are you sure you want to "+
                "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
        if (choice != "Yes, I am sure!"):
            print("Operation canceled.")
            sys.exit(2)

    print()
    print("Creating file " + key_file)
    with open(key_file, "wb") as f:
        f.write(priv)
        f.write(pub)
        f.close()
    print("Creating file " + pubkey_cfile)
    with open(pubkey_cfile, "w") as f:
        f.write(Cfile_Banner)
        f.write(Store_hdr % 1) # One key
        f.write(Slot_hdr % (0, sign_key_type(sign))) 
        i = 0
        for c in bytes(pub[0:-1]):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n\t\t\t')
        f.write("0x%02X" % pub[-1])
        f.write(Pubkey_footer)
        f.write(Slot_footer)
        f.write(Store_footer)
        f.close()
if (sign[0:3] == 'ecc'):
    if (sign == "ecc256"):
        ec = ciphers.EccPrivate.make_key(32)
        ecc_pub_key_len = 64
        qx,qy,d = ec.encode_key_raw()
        if os.path.exists(key_file) and not force:
            choice = input("** Warning: key file already exist! Are you sure you want to "+
                    "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
            if (choice != "Yes, I am sure!"):
                print("Operation canceled.")
                sys.exit(2)

    if (sign == "ecc384"):
        ec = ciphers.EccPrivate.make_key(48)
        ecc_pub_key_len = 96
        qx,qy,d = ec.encode_key_raw()
        if os.path.exists(key_file) and not force:
            choice = input("** Warning: key file already exist! Are you sure you want to "+
                    "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
            if (choice != "Yes, I am sure!"):
                print("Operation canceled.")
                sys.exit(2)

    if (sign == "ecc521"):
        ec = ciphers.EccPrivate.make_key(66)
        ecc_pub_key_len = 132
        qx,qy,d = ec.encode_key_raw()
        if os.path.exists(key_file) and not force:
            choice = input("** Warning: key file already exist! Are you sure you want to "+
                    "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
            if (choice != "Yes, I am sure!"):
                print("Operation canceled.")
                sys.exit(2)

    print()
    print("Creating file " + key_file)
    with open(key_file, "wb") as f:
        f.write(qx)
        f.write(qy)
        f.write(d)
        f.close()
    print("Creating file " + pubkey_cfile)
    with open(pubkey_cfile, "w") as f:
        f.write(Cfile_Banner)
        f.write(Store_hdr % 1) # One key
        f.write(Slot_hdr % (0, sign_key_type(sign))) 
        i = 0
        for c in bytes(qx):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n')
        for c in bytes(qy[0:-1]):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n')
        f.write("0x%02X" % qy[-1])
        f.write(Pubkey_footer)
        f.write(Slot_footer)
        f.write(Store_footer)
        f.close()

if (sign == "rsa2048"):
    rsa = ciphers.RsaPrivate.make_key(2048)
    if os.path.exists(key_file) and not force:
        choice = input("** Warning: key file already exist! Are you sure you want to "+
                "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
        if (choice != "Yes, I am sure!"):
            print("Operation canceled.")
            sys.exit(2)
    priv,pub = rsa.encode_key()
    print()
    print("Creating file " + key_file)
    with open(key_file, "wb") as f:
        f.write(priv)
        f.close()
    print("Creating file " + pubkey_cfile)
    with open(pubkey_cfile, "w") as f:
        f.write(Cfile_Banner)
        f.write(Store_hdr % 1) # One key
        f.write(Slot_hdr % (0, sign_key_type(sign))) 
        i = 0
        for c in bytes(pub):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n')
        f.write(Pubkey_footer)
        f.write(Slot_footer)
        f.write(Store_footer)
        f.close()

if (sign == "rsa3072"):
    rsa = ciphers.RsaPrivate.make_key(3072)
    if os.path.exists(key_file) and not force:
        choice = input("** Warning: key file already exist! Are you sure you want to "+
                "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
        if (choice != "Yes, I am sure!"):
            print("Operation canceled.")
            sys.exit(2)
    priv,pub = rsa.encode_key()
    print()
    print("Creating file " + key_file)
    with open(key_file, "wb") as f:
        f.write(priv)
        f.close()
    print("Creating file " + pubkey_cfile)
    with open(pubkey_cfile, "w") as f:
        f.write(Cfile_Banner)
        f.write(Store_hdr % 1) # One key
        f.write(Slot_hdr % (0, sign_key_type(sign))) 
        i = 0
        for c in bytes(pub):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n')
        f.write(Pubkey_footer)
        f.write(Slot_footer)
        f.write(Store_footer)
        f.close()

if (sign == "rsa4096"):
    rsa = ciphers.RsaPrivate.make_key(4096)
    if os.path.exists(key_file) and not force:
        choice = input("** Warning: key file already exist! Are you sure you want to "+
                "generate a new key and overwrite the existing key? [Type 'Yes, I am sure!']: ")
        if (choice != "Yes, I am sure!"):
            print("Operation canceled.")
            sys.exit(2)
    priv,pub = rsa.encode_key()
    print()
    print("Creating file " + key_file)
    with open(key_file, "wb") as f:
        f.write(priv)
        f.close()
    print("Creating file " + pubkey_cfile)
    with open(pubkey_cfile, "w") as f:
        f.write(Cfile_Banner)
        f.write(Store_hdr % 1) # One key
        f.write(Slot_hdr % (0, sign_key_type(sign))) 
        i = 0
        for c in bytes(pub):
            f.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                f.write('\n')
        f.write(Pubkey_footer)
        f.write(Slot_footer)
        f.write(Store_footer)
        f.close()
