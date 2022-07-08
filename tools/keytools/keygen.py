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
    print("Usage: %s [--ed25519 | --ed448 | --ecc256 | --ecc384 | --ecc521 | --rsa2048| --rsa3072 | --rsa4096] [ --force ] key0.der [key1.der key2.der ... keyN.der]\n" % sys.argv[0])
    parser.print_help()
    sys.exit(1)

def dupsign():
    print("")
    print("Error: only one algorithm must be specified.")
    print("")
    usage()

def sign_key_type(name):
    if name == 'ed25519':
        return 'AUTH_KEY_ED25519'
    elif name == 'ed448':
        return 'AUTH_KEY_ED448'
    elif name == 'ecc256':
        return 'AUTH_KEY_ECC256'
    elif name == 'ecc384':
        return 'AUTH_KEY_ECC384'
    elif name == 'ecc521':
        return 'AUTH_KEY_ECC521'
    elif name == 'rsa2048':
        return 'AUTH_KEY_RSA2048'
    elif name == 'rsa3072':
        return 'AUTH_KEY_RSA3072'
    elif name == 'rsa4096':
        return 'AUTH_KEY_RSA4096'
    else:
        return 0

Cfile_Banner="/* Keystore file for wolfBoot, automatically generated. Do not edit.  */\n"+ \
             "/*\n" + \
             " * This file has been generated and contains the public keys\n"+ \
             " * used by wolfBoot to verify the updates.\n"+ \
             " */" \
             "\n#include <stdint.h>\n#include \"wolfboot/wolfboot.h\"\n" \
             "#ifdef WOLFBOOT_NO_SIGN\n\t#define NUM_PUBKEYS 0\n#else\n\n" \
             "#if (KEYSTORE_PUBKEY_SIZE != KEYSTORE_PUBKEY_SIZE_%s)\n\t" \
             "#error Key algorithm mismatch. Remove old keys via 'make distclean'\n" \
             "#else\n"


Store_hdr = "#define NUM_PUBKEYS %d\nconst struct keystore_slot PubKeys[NUM_PUBKEYS] = {\n\n"
Slot_hdr  = "\t /* Key associated to private key '%s' */\n"
Slot_hdr += "\t{\n\t\t.slot_id = %d,\n\t\t.key_type = %s,\n"
Slot_hdr += "\t\t.part_id_mask = KEY_VERIFY_ALL,\n\t\t.pubkey_size = %s,\n"
Slot_hdr += "\t\t.pubkey = {\n\t\t\t"
Pubkey_footer = "\n\t\t},"
Slot_footer = "\n\t},\n\n"
Store_footer = '\n};\n\n'

Keystore_API =  "int keystore_num_pubkeys(void)\n"
Keystore_API += "{\n"
Keystore_API += "    return NUM_PUBKEYS;\n"
Keystore_API += "}\n\n"
Keystore_API += "uint8_t *keystore_get_buffer(int id)\n"
Keystore_API += "{\n"
Keystore_API += "    if (id >= keystore_num_pubkeys())\n"
Keystore_API += "        return (uint8_t *)0;\n"
Keystore_API += "    return (uint8_t *)PubKeys[id].pubkey;\n"
Keystore_API += "}\n\n"
Keystore_API += "int keystore_get_size(int id)\n"
Keystore_API += "{\n"
Keystore_API += "    if (id >= keystore_num_pubkeys())\n"
Keystore_API += "        return -1;\n"
Keystore_API += "    return (int)PubKeys[id].pubkey_size;\n"
Keystore_API += "}\n\n"
Keystore_API += "uint32_t keystore_get_mask(int id)\n"
Keystore_API += "{\n"
Keystore_API += "    if (id >= keystore_num_pubkeys())\n"
Keystore_API += "        return -1;\n"
Keystore_API += "    return (int)PubKeys[id].part_id_mask;\n"
Keystore_API += "}\n\n"
Keystore_API += "#endif /* Keystore public key size check */\n"
Keystore_API += "#endif /* WOLFBOOT_NO_SIGN */\n"








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
parser.add_argument('keyfile', nargs='+')

args=parser.parse_args()

#sys.exit(0) #test

pubkey_cfile = "src/keystore.c"
key_files = args.keyfile


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
    print("ecc521 keys are not yet supported!")
    sys.exit(1)
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

# Create/open public key c file
print ("Output C file:        " + pubkey_cfile)
pfile = open(pubkey_cfile, "w")
pfile.write(Cfile_Banner % sign.upper())
pfile.write(Store_hdr % len(key_files))


for slot_index, key_file in enumerate(key_files):
    print ("Public key slot:      " + str(slot_index))
    print ("Selected cipher:      " + sign)
    print ("Output Private key:   " + key_file)
    print()
    if os.path.exists(key_file) and not force:
        choice = input("** Warning: key file already exist! Are you sure you want to "+
                "generate a new key and overwrite the existing key? [Type 'Yes']: ")
        if (choice != "Yes"):
            print("Operation canceled.")
            sys.exit(2)

    if (sign == "ed25519"):
        ed = ciphers.Ed25519Private.make_key(32)
        priv,pub = ed.encode_key()

        print()
        print("Creating file " + key_file)
        with open(key_file, "wb") as f:
            f.write(priv)
            f.write(pub)
            f.close()
        print("Creating file " + pubkey_cfile)
        pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
            "KEYSTORE_PUBKEY_SIZE_ED25519"))
        i = 0
        for c in bytes(pub[0:-1]):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        pfile.write("0x%02X" % pub[-1])
        pfile.write(Pubkey_footer)
        pfile.write(Slot_footer)

    if (sign == "ed448"):
        ed = ciphers.Ed448Private.make_key(57)
        priv,pub = ed.encode_key()
        print()
        print("Creating file " + key_file)
        with open(key_file, "wb") as f:
            f.write(priv)
            f.write(pub)
            f.close()
        print("Creating file " + pubkey_cfile)
        pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
            "KEYSTORE_PUBKEY_SIZE_ED448"))
        i = 0
        for c in bytes(pub[0:-1]):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        pfile.write("0x%02X" % pub[-1])
        pfile.write(Pubkey_footer)
        pfile.write(Slot_footer)
    if (sign[0:3] == 'ecc'):
        if (sign == "ecc256"):
            ec = ciphers.EccPrivate.make_key(32)
            ecc_pub_key_len = 64
            qx,qy,d = ec.encode_key_raw()
            pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
                "KEYSTORE_PUBKEY_SIZE_ECC256"))

        if (sign == "ecc384"):
            ec = ciphers.EccPrivate.make_key(48)
            ecc_pub_key_len = 96
            qx,qy,d = ec.encode_key_raw()
            pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
                "KEYSTORE_PUBKEY_SIZE_ECC384"))

        if (sign == "ecc521"):
            ec = ciphers.EccPrivate.make_key(66)
            ecc_pub_key_len = 132
            qx,qy,d = ec.encode_key_raw()
        print()
        print("Creating file " + key_file)
        with open(key_file, "wb") as f:
            f.write(qx)
            f.write(qy)
            f.write(d)
            f.close()
        print("Creating file " + pubkey_cfile)
        i = 0
        for c in bytes(qx):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        for c in bytes(qy[0:-1]):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        pfile.write("0x%02X" % qy[-1])
        pfile.write(Pubkey_footer)
        pfile.write(Slot_footer)

    if (sign == "rsa2048"):
        rsa = ciphers.RsaPrivate.make_key(2048)
        priv,pub = rsa.encode_key()
        print()
        print("Creating file " + key_file)
        with open(key_file, "wb") as f:
            f.write(priv)
            f.close()
        print("Creating file " + pubkey_cfile)
        pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
            str(len(pub))))
        i = 0
        for c in bytes(pub):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        pfile.write(Pubkey_footer)
        pfile.write(Slot_footer)

    if (sign == "rsa3072"):
        rsa = ciphers.RsaPrivate.make_key(3072)
        priv,pub = rsa.encode_key()
        print()
        print("Creating file " + key_file)
        with open(key_file, "wb") as f:
            f.write(priv)
            f.close()
        print("Creating file " + pubkey_cfile)
        pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
            str(len(pub))))
        i = 0
        for c in bytes(pub):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        pfile.write(Pubkey_footer)
        pfile.write(Slot_footer)

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
        pfile.write(Slot_hdr % (key_file, slot_index, sign_key_type(sign),
            str(len(pub))))

        i = 0
        for c in bytes(pub):
            pfile.write("0x%02X, " % c)
            i += 1
            if (i % 8 == 0):
                pfile.write('\n\t\t\t')
        pfile.write(Pubkey_footer)
        pfile.write(Slot_footer)

pfile.write(Store_footer)
pfile.write(Keystore_API)
pfile.close()
