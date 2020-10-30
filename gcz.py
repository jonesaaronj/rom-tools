#!/usr/bin/env python3

import argparse
import forcecrc
import io
import logging
import struct
import sys
import zlib
import os
import tempfile
from typing import BinaryIO
from typing import List

GCZ_MAGIC = 0xB10BC001

WII_MAGIC = 0xA39E1C5D
WII_MAGIC_OFFSET = 0x018
GC_MAGIC = 0x3D9F33C2
GC_MAGIC_OFFSET = 0x01C
NKIT_MAGIC = 0x54494B4E
NKIT_MAGIC_OFFSET = 0x200

GCZ_SUBTYPE_GC = 0x00
GCZ_SUBTYPE_WII = 0x01
GCZ_SUBTYPE_NKIT = 0xFFFFFFFF
GCZ_SUBTYPE_OFFSET = 0x04


class Header:
    def __init__(
        self,
        f: BinaryIO = None,
        magic: int = GCZ_MAGIC,
        sub_type: int = 0,
        compressed_data_size: int = 0,
        data_size: int = 0,
        block_size: int = 0,
        num_blocks: int = 0,
        block_pointers: List[int] = [],
        hashes: List[int] = [],
    ):
        self.magic = magic
        self.sub_type = sub_type
        self.compressed_data_size = compressed_data_size
        self.data_size = data_size
        self.block_size = block_size
        self.num_blocks = num_blocks
        self.block_pointers = block_pointers
        self.hashes = hashes

        if f is not None:
            self.magic = struct.unpack("I", f.read(4))[0]
            if self.magic != GCZ_MAGIC:
                raise Exception("GCZ Magic Packet Not Found")

            self.sub_type = struct.unpack("I", f.read(4))[0]
            self.compressed_data_size = struct.unpack("Q", f.read(8))[0]
            self.data_size = struct.unpack("Q", f.read(8))[0]
            self.block_size = struct.unpack("I", f.read(4))[0]
            self.num_blocks = struct.unpack("I", f.read(4))[0]

            for _ in range(self.num_blocks):
                block_pointer = struct.unpack("Q", f.read(8))[0]
                self.block_pointers.append(block_pointer)

            for _ in range(self.num_blocks):
                hash = struct.unpack("I", f.read(4))[0]
                self.hashes.append(hash)

    def size(self):
        return 32 + (8 * self.num_blocks) + (4 * self.num_blocks)

    def block_pointer_start(self):
        return 32

    def hashes_start(self):
        return 32 + (8 * self.num_blocks)

    def crc(self, crc: int = 0):
        for b in self.generator():
            crc = zlib.crc32(b, crc)
        return crc

    def generator(self):
        yield struct.pack("I", self.magic)
        yield struct.pack("I", self.sub_type)
        yield struct.pack("Q", self.compressed_data_size)
        yield struct.pack("Q", self.data_size)
        yield struct.pack("I", self.block_size)
        yield struct.pack("I", self.num_blocks)
        for block_pointer in self.block_pointers:
            yield struct.pack("Q", block_pointer)
        for hsh in self.hashes:
            yield struct.pack("I", hsh)
           
    def log(self, level):
        logger.log(level, "Magic:             {0} {1}".format(("0x%08x" % self.magic), ("%10d" % self.magic)))
        logger.log(level, "Sub Type:          {0} {1}".format(("0x%08x" % self.sub_type), ("%10d" % self.sub_type)))
        logger.log(level, "Compressed Size:   {0} {1}".format(("0x%08x" % self.compressed_data_size), ("%10d" % self.compressed_data_size)))
        logger.log(level, "Uncompressed Size: {0} {1}".format(("0x%08x" % self.data_size), ("%10d" % self.data_size)))
        logger.log(level, "Block Size:        {0} {1}".format(("0x%08x" % self.block_size), ("%10d" % self.block_size)))
        logger.log(level, "Number of Blocks:  {0} {1}".format(("0x%08x" % self.num_blocks), ("%10d" % self.num_blocks)))


def decompress(f: BinaryIO):

    header = Header(f)
    header.log(logging.INFO)

    for block_num in range(header.num_blocks):
        logger.debug("Processing Block {0} of {1}".format(block_num + 1, header.num_blocks))

        is_last_block = block_num == header.num_blocks - 1

        block_not_compressed = bool(header.block_pointers[block_num] & (1 << 63))
        block_pointer = header.block_pointers[block_num] & ~(1 << 63)
        block_pointer_next = header.compressed_data_size if is_last_block else header.block_pointers[block_num + 1] & ~(1 << 63)
        block_len = block_pointer_next - block_pointer

        logger.debug("Reading {0} bytes".format(hex(block_len)))
        compressed_block = f.read(block_len)

        hash = zlib.adler32(compressed_block)
        if hash != header.hashes[block_num]:
            raise Exception("Hash Error: {0} does not match {1} in block {2}"
                            .format(hex(hash), hex(header.hashes[block_num]), block_num + 1))

        if block_not_compressed:
            logger.debug("Block not compressed")
            uncompressed_block = compressed_block
        else:
            uncompressed_block = zlib.decompress(compressed_block, bufsize = header.block_size)

        if len(uncompressed_block) != header.block_size:
            raise Exception("Block Size Error: {0} does not match block size of {1}"
                            .format(hex(len(uncompressed_block)), hex(header.block_size)))

        logger.debug("Compressed Block Size   {0} {1}"
                     .format(hex(len(compressed_block)), len(compressed_block)))
        logger.debug("Uncompressed Block Size {0} {1}"
                     .format(hex(len(uncompressed_block)), len(uncompressed_block)))

        if is_last_block:
            trimmed_block = uncompressed_block
            i = len(uncompressed_block)
            while all(b == 0 for b in trimmed_block[i-2048-1:i-1]) and i != 0:
                trimmed_block = trimmed_block[0:i-2048]
                i -= 2048
            yield trimmed_block

        else:
            yield uncompressed_block

    header.log(logging.DEBUG)


def compress(f: BinaryIO, block_size: int, compression_threshold_percent: int):
    #buffer = tempfile.NamedTemporaryFile(mode="x+b", delete=True)
    #logger.debug("Using tmp file {0}".format(buffer.name))

    buffer = io.BytesIO()
    
    sub_type = -1
    compressed_data_size = 0
    data_size = 0
    num_blocks = 0
    block_pointers = []
    hashes = []
    source_crc = 0
    for block in iter(lambda: f.read(block_size), b''):
        if sub_type == -1:
            nkit_magic = struct.unpack("I", block[NKIT_MAGIC_OFFSET: NKIT_MAGIC_OFFSET + 4])[0]
            wii_magic = struct.unpack("I", block[WII_MAGIC_OFFSET: WII_MAGIC_OFFSET + 4])[0]
            gc_magic = struct.unpack("I", block[GC_MAGIC_OFFSET: GC_MAGIC_OFFSET + 4])[0]
            if NKIT_MAGIC == nkit_magic:
                logger.info("GCZ subtype set to NKIT")
                sub_type = GCZ_SUBTYPE_NKIT
            elif WII_MAGIC == wii_magic:
                logger.info("GCZ subtype set to WII")
                sub_type = GCZ_SUBTYPE_WII
            elif GC_MAGIC == gc_magic:
                logger.info("GCZ subtype set to GC")
                sub_type = GCZ_SUBTYPE_GC
            else:
                raise Exception("Unable to determine sub_type")

        num_blocks += 1
        block_len = len(block)
        padding_len = 0
        if sub_type == GCZ_SUBTYPE_NKIT and block_len < block_size:
            padding_len = block_size - block_len
            logger.debug("Padding Last Block {0} bytes".format(padding_len))

        logger.debug("Processing block of size {0}".format(block_len))
        compressed_block = zlib.compress(bytes(bytearray(block) + bytearray(padding_len)), zlib.Z_BEST_COMPRESSION)
        compressed_block_len = len(compressed_block)
        compression_ratio = int(compressed_block_len / block_len * 100)
        if compression_ratio >= compression_threshold_percent:
            logger.debug("Uncompressed block used")
            compressed_block = block
            compressed_block_len = block_len
            block_pointers.append(compressed_data_size | (1 << 63))
        else:
            logger.debug("Compressed block to {0}".format(compressed_block_len))
            logger.debug("Compressed ratio {0}%".format(compression_ratio))
            block_pointers.append(compressed_data_size)

        buffer.write(compressed_block)
        source_crc = zlib.crc32(block, source_crc)
        data_size += block_len
        compressed_data_size += compressed_block_len
        hsh = zlib.adler32(compressed_block)
        hashes.append(hsh)

    if num_blocks != len(block_pointers):
        raise Exception("Block Count Error {0} {1}".format(num_blocks, len(block_pointers)))

    if num_blocks != len(hashes):
        raise Exception("Block Count Error {0} {1}".format(num_blocks, len(hashes)))

    logger.info("Creating header")
    header = Header(
        magic=GCZ_MAGIC,
        sub_type=sub_type,
        compressed_data_size=compressed_data_size,
        data_size=data_size,
        block_size=block_size,
        num_blocks=num_blocks,
        block_pointers=block_pointers,
        hashes=hashes,
    )

    if GCZ_SUBTYPE_NKIT == sub_type:
        buffer_crc = data_crc(buffer, header.crc())
        fix_crc = forcecrc.Calculate(buffer_crc, compressed_data_size + header.size(), source_crc, GCZ_SUBTYPE_OFFSET, GCZ_SUBTYPE_NKIT)
        header.sub_type = fix_crc
        logger.info("Generating crc for nkit sub_type")
        logger.debug("  source crc: {0}".format(hex(source_crc)))
        logger.debug("  buffer crc: {0}".format(hex(buffer_crc)))
        logger.debug("  fix crc:    {0}".format(hex(fix_crc)))

    logger.info("Generating header of size {0} {1}".format(hex(header.size()), header.size()))
    logger.debug("  pointers starting at {0} {1}".format(hex(header.block_pointer_start()), header.block_pointer_start()))
    logger.debug("  hashes starting at {0} {1}".format(hex(header.hashes_start()), header.hashes_start()))
    yield from header.generator()

    logger.info("Generating data starting at {0} {1}".format(hex(header.size()), header.size()))
    yield from data_generator(buffer)


def data_generator(buffer: BinaryIO):
    buffer.seek(0)
    for block in iter(lambda: buffer.read(1024), b""):
        yield block


def data_crc(buffer: BinaryIO, crc: int = 0):
    buffer.seek(0)
    for block in iter(lambda: buffer.read(1024), b""):
        crc = zlib.crc32(block, crc)
    return crc


def decompress_main(args):
    for block in decompress(args.input):
        args.output.write(block)
    args.output.close()
    args.input.close()


def compress_main(args):
    for block in compress(args.input, args.block_size, args.compression_threshold_percent):
        args.output.write(block)
    args.output.close()
    args.input.close()


def option_parse():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_compress = subparsers.add_parser("compress")
    parser_compress.set_defaults(func=compress_main)
    parser_compress.add_argument(
        "-i",
        "--input",
        nargs="?",
        type=argparse.FileType("rb"),
        default=sys.stdin.buffer,
        help="(default: stdin)",
    )
    parser_compress.add_argument(
        "-o",
        "--output",
        nargs="?",
        type=argparse.FileType("xb"),
        default=sys.stdout.buffer,
        help="(default: stdout)",
    )
    parser_compress.add_argument(
        "-b",
        "--block_size",
        type=int,
        default=0x4000,
        help="(default: %(default)s)"
    )
    parser_compress.add_argument(
        "-t",
        "--compression_threshold_percent",
        type=lambda x: (int(x) <= 100) and int(
            x) or sys.exit("Maximum percent is 100"),
        default=100,
        help="(default: %(default)s, max: 100)",
    )

    parser_decompress = subparsers.add_parser("decompress")
    parser_decompress.set_defaults(func=decompress_main)
    parser_decompress.add_argument(
        "-i",
        "--input",
        nargs="?",
        type=argparse.FileType("rb"),
        default=sys.stdin.buffer,
        help="(default: stdin)",
    )
    parser_decompress.add_argument(
        "-o",
        "--output",
        nargs="?",
        type=argparse.FileType("xb"),
        default=sys.stdout.buffer,
        help="(default: stdout)",
    )

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    root = logging.getLogger()
    root.setLevel(logging.ERROR)
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    root.addHandler(ch)
    logger = logging.getLogger(__name__)

    option_parse()

sys.exit(0)
