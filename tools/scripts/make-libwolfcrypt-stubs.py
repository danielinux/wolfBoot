#!/usr/bin/python3
import re,os

outfilename = 'wolfcrypt_stubs.c'

f = open("wolfboot.map", "r")
functs = []
included_files = []
proto_dict = {}
address_dict = {}
fn_args_dict = {}
api_list = []

while True:
    line = f.readline()
    if line == "":
        break
    if re.search("^ \.text\.wc_", line):
        fun = line.strip(" .text.").rstrip('\n')
        if " " in fun:
            fun = fun.split(" ")[0]
        found = ""
        while(found == ""):
            for word in line.split(" "):
                if word.startswith("0x") and len(word) > 4:
                    address_dict[fun] = word
                    found = word
                    break
            if found:
                break
            else:
                line = f.readline()
        functs.append(fun)


wc_include_list = os.listdir("lib/wolfssl/wolfssl/wolfcrypt")

for hf in wc_include_list:
    if hf.endswith(".h"):
        fph = open('lib/wolfssl/wolfssl/wolfcrypt/'+hf, "r")
        proto = ""
        for sym in functs:
            fph.seek(0)
            while True:
                line = fph.readline()
                if line == "":
                    break
                if " " + sym + "(" in line:
                    if "WOLFSSL_API" in line:
                        proto = line
                        while not ';' in proto:
                            proto += fph.readline()
                        if hf not in included_files:
                            included_files.append(hf)
                        pro_clean = re.sub("^.*WOLFSSL_API ", "", proto.rstrip('\n'))
                        pro_clean = re.sub("\n","", pro_clean)
                        while ('  ' in pro_clean):
                            pro_clean = re.sub('  ', ' ', pro_clean)
                        typeargfield = re.sub("^.*\(", "", pro_clean)
                        typeargfield = re.sub("\).*$", "", typeargfield)
                        args = ""
                        if (typeargfield == "void"):
                            fn_args_dict[sym] = ""
                        else:
                            for typearg in typeargfield.split(','):
                                a = typearg.split(' ')[-1]
                                if (a.startswith('*')):
                                    a = a.strip('*')
                                args += a + ', '
                            fn_args_dict[sym] = args.rstrip(', ')
                        proto_dict[sym] = pro_clean
                        api_list.append(sym)
                    break
        fph.close()


## Create file

os.unlink(outfilename)

outfile = open(outfilename, 'w+')

outfile.write("/* This file is automatically generate. DO NOT EDIT! */\n\n\n")

for i in included_files:
    outfile.write('#include "wolfssl/wolfcrypt/'+i+'"\n')

outfile.write("\n\n")

for i in api_list:
    pro = proto_dict[i]
    definition = re.sub(" " + i + "\(", " (*stub_" + i + ")(", pro).rstrip(';')
    outfile.write(definition + ' = (void *)' + address_dict[i] + ' + 1U;\n')

outfile.write("\n\n")


for i in api_list:
    pro = proto_dict[i]
    definition = pro.rstrip(';') + '\n{\n'
    definition += '    return stub_' + i +'(' + fn_args_dict[i] + ');\n}\n\n'
    outfile.write(definition)

