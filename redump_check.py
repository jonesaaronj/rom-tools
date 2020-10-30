#!/usr/bin/env python3

import argparse
import binascii
import gcz
import hashlib
import json
import libarchive.public
import locale
import os
import shutil
import struct
import sys
import xml.etree.ElementTree

def option_parse():
    parser = argparse.ArgumentParser(description="Redump")

    parser.add_argument("-d", "--dat_file",
                        dest="dat_file",
                        required=True,
                        help="set dat file")

    parser.add_argument("-a", "--have_file",
                        dest="have_file",
                        required=True,
                        help="set have file")

    parser.add_argument("-m", "--missing_file",
                        dest="missing_file",
                        required=True,
                        help="set missing file")

    parser.add_argument("-r", "--rom_folder",
                        dest="rom_folder",
                        required=True,
                        help="set rom folder")

    parser.add_argument("-b", "--bad_folder",
                        dest="bad_folder",
                        required=True,
                        help="set bad folder")

    parser.add_argument("-g", "--region",
                        dest="region",
                        required=False,
                        help="set region")

    args = parser.parse_args()
    return args.dat_file, args.have_file, args.missing_file, args.rom_folder, args.bad_folder, args.region

def create_hashes(gen):
    #size = 0
    crc = 0
    #sha1hash = hashlib.sha1()
    #md5hash = hashlib.md5()
    for b in gen:
        #size += len(b)
        crc = binascii.crc32(b, crc)
        #sha1hash.update(b)
        #md5hash.update(b)
    crc = ("%08x" % (crc & 0xfffffffff))
    #sha1 = sha1hash.hexdigest()
    #md5 = md5hash.hexdigest()
    hashes = json.dumps({
        #"size": str(size),
        "crc": crc.lower(),
        #"md5": md5.lower(),
        #"sha1": sha1.lower(),
    })
    # print(hashes)
    return hashes

def handle_match(db, hashes, filename, badFilename, dirpath, have_db, have_file):
    if hashes in db:
        names = db[hashes]
        print("Found in db %s" % names)
        newFilename = os.path.join(os.path.normpath(dirpath), names[0])
        shutil.move(filename, newFilename)
        have_db[names[0]] = hashes
        for name in names[1:]:
            newFilenameCopy = os.path.join(os.path.normpath(dirpath), name)
            shutil.copy(newFilename, newFilenameCopy)
            have_db[name] = hashes
        del db[hashes]
        write_have(have_db, have_file)
    else:
        print("move")
        # shutil.move(filename, badFilename)

def handle_archive(f):
    with libarchive.public.memory_reader(f.read()) as e:
        for entry in e:
            for block in entry.get_blocks():
                yield block

def parse_folder(db, have_db, have_file, rom_folder, bad_folder):
    for dirpath, _, filenames in os.walk(rom_folder):
        if filenames:
            for f in filenames:
                if f == ".have" or f == ".have.sha1" or f == ".have.md5" or f == ".missing" or f in have_db: continue
                filename = os.path.join(os.path.normpath(dirpath), f)
                badFilename = os.path.join(os.path.normpath(bad_folder), f)
                print("Processing file %s" % (filename))
                with open(filename, "rb", buffering=0) as f:

                    PKZ_MAGIC = 0x504B0304
                    P7Z_MAGIC = 0x377ABCAF

                    magic = struct.unpack('L', f.read(4))[0]

                    if (magic == gcz.GCZ_MAGIC):
                        print("Found GCZ Header")
                        f.seek(0)
                        gcz_generator = gcz.decompress(f)
                        hashes = create_hashes(gcz_generator)
                        handle_match(db, hashes, filename, badFilename, dirpath, have_db, have_file)

                    elif (magic == PKZ_MAGIC):
                        print("Found PKZ Header")
                        f.seek(0)
                        pkz_generator = handle_archive(f)
                        hashes = create_hashes(pkz_generator)
                        handle_match(db, hashes, filename, badFilename, dirpath, have_db, have_file)

                    elif (magic == P7Z_MAGIC):
                        print("Found P7Z Header")
                        f.seak(0)
                        p7z_generator = handle_archive(f)
                        hashes = create_hashes(p7z_generator)
                        handle_match(db, hashes, filename, badFilename, dirpath, have_db, have_file)

                    else:
                        print("Found Rom")
                        f.seek(0)
                        generator = iter(lambda : f.read(1024), b'')
                        hashes = create_hashes(generator)
                        handle_match(db, hashes, filename, badFilename, dirpath, have_db, have_file)

def create_database(db, dat_file, region):
    total_number_of_entries = 0
    print("Opening " + dat_file)
    e = xml.etree.ElementTree.parse(dat_file).getroot()

    for game in e.findall('game'):
        for rom in game.findall('rom'):
            hashes = json.dumps({
                "size": rom.get('size').lower(),
                "crc": rom.get('crc').lower(),
                "md5": rom.get('md5').lower(),
                "sha1": rom.get('sha1').lower(),
            })
            name = rom.get('name')
            if not region or region in name:
                print("Adding " + name)
                total_number_of_entries += 1
                if hashes not in db:
                    db[hashes] = [name]
                else:
                    db[hashes].append(name)

    print("%s entries found" % total_number_of_entries)
    return total_number_of_entries

def process_have(db, have_db, have_file):
    total_number_of_entries = 0
    with open(have_file, "r") as file:
        for line in file:
            hashes, name = line.strip().split('\t', 1)
            if hashes in db and name in db[hashes]:
                total_number_of_entries += 1
                print("Removing " + name)
                while name in db[hashes]: db[hashes].remove(name)
                if not db[hashes]: del db[hashes]
                have_db[name] = hashes
    print("%s entries removed" % total_number_of_entries)
    return total_number_of_entries

def write_have(have_db, have_file):
    with open(have_file, 'w') as have_f:
        for name, key in have_db.items():
            have_f.write("%s\t%s\n" % (key, name))

def write_have_hashes(have_db, have_file):
    with open(have_file + ".md5", 'w') as have_f:
        for name, hashes in have_db.items():
            hashes = json.loads(hashes)
            have_f.write("%s\t%s\n" % (hashes['md5'], name))
    with open(have_file + ".sha1", 'w') as have_f:
        for name, hashes in have_db.items():
            hashes = json.loads(hashes)
            have_f.write("%s\t%s\n" % (hashes['sha1'], name))

def write_missing(db, missing_file):
    with open(missing_file, 'w') as missing_f:
        for hashes, names in db.items():
            for name in names:
                missing_f.write("%s\t%s\n" % (hashes, name))

if __name__ == '__main__':

    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

    DAT_FILE, HAVE_FILE, MISSING_FILE, ROM_FOLDER, BAD_FOLDER, REGION = option_parse()

    DB = dict()
    HAVE_DB = dict()
    entries = create_database(DB, DAT_FILE, REGION)
    entries = process_have(DB, HAVE_DB, HAVE_FILE)
    parse_folder(DB, HAVE_DB, HAVE_FILE, ROM_FOLDER, BAD_FOLDER)
    write_have(HAVE_DB, HAVE_FILE)
    write_have_hashes(HAVE_DB, HAVE_FILE)
    write_missing(DB, MISSING_FILE)

sys.exit(0)