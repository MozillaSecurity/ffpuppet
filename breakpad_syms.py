#!/usr/bin/env python
# coding=utf-8
import binascii
import json
import logging
import os.path
import re
import struct
import sys
import time


log = logging.getLogger("breakpad") # pylint: disable=invalid-name
bs_log = logging.getLogger("bisect") # pylint: disable=invalid-name
bs_log.setLevel(logging.INFO)


def get_macho_debug_hash(input_file):
    """
    Get the debug hash for a x86_64 Mach-O file.

    @type input_file: file
    @param input_file: Open file handle to Mach-O file.

    @rtype: str or None
    @return: Debug hash of the file, or None on error.
    """
    #ref: https://chromium.googlesource.com/breakpad/breakpad/+/master/src/common/mac/macho_id.cc
    # try uuid first
    start_time = time.time()
    # make sure this is a Mach-O
    input_file.seek(0)
    if input_file.read(8) != b"\xCF\xFA\xED\xFE\x07\0\0\x01":
        input_file.seek(0)
        log.warning("Invalid Mach-O header: %r", input_file.read(8))
        return None
    input_file.seek(0x10)
    ncmds = struct.unpack("<I", input_file.read(4))[0]
    input_file.seek(0x20)
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", input_file.read(8))
        if cmd == 0x1B: # LC_UUID
            result = "%s0" % binascii.b2a_hex(input_file.read(cmdsize - 8)).upper()
            log.debug("generated hash for %s: %s (elapsed %0.1fs)", input_file.name, result, time.time() - start_time)
            return result
        input_file.seek(cmdsize - 8, 1)
    log.debug("failed to generate hash for %s (elapsed %0.1fs)", input_file.name, time.time() - start_time)
    return None


def get_elf_debug_hash(input_file):
    """
    Get the debug hash for a 64-bit ELF file.

    @type input_file: file
    @param input_file: Open file handle to ELF file.

    @rtype: str or None
    @return: Debug hash of the file, or None on error.
    """
    start_time = time.time()
    # make sure this is ELF
    input_file.seek(0)
    if input_file.read(7) != b"\x7FELF\x02\x01\x01":
        input_file.seek(0)
        log.warning("Invalid ELF header: %r", input_file.read(7))
        return None
    # locate section table
    input_file.seek(0x28)
    shoff = struct.unpack("<Q", input_file.read(8))[0]
    input_file.seek(0x3E)
    shstridx = struct.unpack("<H", input_file.read(2))[0]
    # read the strtab
    input_file.seek(shoff + shstridx * 0x40)
    fields = struct.unpack("<IIQQQQIIQQ", input_file.read(0x40))
    sh_offset = fields[4]
    sh_size = fields[5]
    input_file.seek(sh_offset)
    strtab = input_file.read(sh_size)
    # find .note.gnu.build-id
    input_file.seek(shoff)
    while input_file:
        #sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
        fields = struct.unpack("<IIQQQQIIQQ", input_file.read(0x40))
        sh_name = fields[0]
        name = strtab[sh_name:strtab.index(b"\0", sh_name)]
        if name == ".note.gnu.build-id":
            # found it, now dump it
            sh_offset = fields[4]
            sh_size = fields[5]
            input_file.seek(sh_offset)
            name_size, hash_size, _ = struct.unpack("<III", input_file.read(12))
            input_file.seek(name_size, 1)
            hash_ = input_file.read(hash_size)
            # now muck it up
            fields = list(struct.unpack("<IHH", hash_[:8]))
            fields.extend(struct.unpack(">Q", hash_[8:16]))
            result = "%08X%04X%04X%016X0" % tuple(fields)
            log.debug("generated hash for %s: %s (elapsed %0.1fs)", input_file.name, result, time.time() - start_time)
            return result
    log.debug("failed to generate hash for %s (elapsed %0.1fs)", input_file.name, time.time() - start_time)
    return None


def bisect_bin(input_file, value, prefix="", key=lambda x:x, lo=0, hi=None):
    """
    Similar to stdlib bisect.bisect_right(), but do line-based bisection in an open file-handle.
    ValueError or AssertionError is raised on error.

    @type input_file: file
    @param input_file: Open file handle to search within.

    @type prefix: str
    @param prefix: Only care about lines starting with this prefix.

    @type value: orderable with return type of param key
    @param value: Value to search for within the file.

    @type key: function
    @param key: Function to extract the comparison key from a line of text.
                Return type must be orderable with param value.

    @type lo: int or long
    @param lo: Starting offset to search from.

    @type hi: int or long
    @param hi: Maximum offset to search within.

    @rtype: int or long
    @return: File offset of the line <= the search value.
    """
    # based on Lib/bisect.py in python2.7 src
    if hi is None:
        input_file.seek(0, 2)
        hi = input_file.tell()
    assert hi > lo
    orig_lo = lo
    orig_hi = hi
    bs_log.debug("bisecting %sfor %x between [%d, %d]", prefix, value, lo, hi)
    old_mid = None
    while lo < hi:
        mid = (lo + hi) // 2
        if mid == old_mid:
            bs_log.debug("repeated mid value, breaking")
            break
        old_mid = mid
        bs_log.debug("  checking %d", mid)
        # find next instance of prefix >= the midpoint
        # also ensure prefix is preceded by newline, or beginning of file
        if mid == 0:
            on_eol = True
            input_file.seek(0)
        else:
            input_file.seek(mid - 1)
            on_eol = (input_file.read(1) == '\n')
        if on_eol:
            bs_log.debug("  %d is already on EOL", mid)
        while mid < hi:
            buf = input_file.readline()
            if not on_eol:
                bs_log.debug("  found EOL at %d", mid + len(buf))
                on_eol = True
            elif buf.startswith(prefix):
                bs_log.debug("  found %s at %d", prefix, mid)
                break
            mid += len(buf)
        else:
            # no prefix could be found before we hit end
            hi = old_mid
            bs_log.debug("no prefix, setting end to mid: %d", hi)
            continue
        assert mid < orig_hi
        key_value = key(buf)
        bs_log.debug("  value here is %x", key_value)
        if value < key_value:
            hi = mid
        else:
            lo = mid + 1
        bs_log.debug("  updated range to [%d, %d]", lo, hi)
    if lo == orig_lo:
        raise ValueError
    lo -= 1
    bs_log.debug("  ==> returning %d", lo)
    return lo


class SymbolsFile(object):
    """
    Class representing a symbol table of an executable.
    """

    def __init__(self):
        """
        Constructor for an empty SymbolsFile object
        """
        self.files = []
        self.funcs = []
        self.publics = []
        self.sym_fp = None

    @classmethod
    def from_binary(cls, input_file, symbols_path=None):
        """
        Factory method for a SymbolsFile object from a binary.

        @type input_file: str
        @param input_file: Path to a breakpad symbol file.

        @type symbols_path: str
        @param symbols_path: Override the path to search for breakpad symbols. By default will look
                             for a folder named 'symbols' in the same folder as the binary.

        @rtype: SymbolsFile
        @return: A SymbolsFile object initialized from the given breakpad symbols.
        """
        with open(input_file, "rb") as exe_fp:
            if sys.platform == "linux2":
                hash_ = get_elf_debug_hash(exe_fp)
            elif sys.platform == "darwin":
                hash_ = get_macho_debug_hash(exe_fp)
            else:
                raise Exception("Unsupported platform: %s" % sys.platform)
        sym_path = symbols_path or os.path.join(os.path.dirname(input_file), "symbols")
        sym_path = os.path.join(sym_path, os.path.basename(input_file))
        sym_path = os.path.join(sym_path, hash_, "%s.sym" % os.path.basename(input_file))
        return cls.from_breakpad_sym_file(sym_path)

    @classmethod
    def from_breakpad_sym_file(cls, input_file):
        """
        Factory method for a SymbolsFile object from a breakpad symbol file.

        @type input_file: str
        @param input_file: Path to a breakpad symbol file.

        @rtype: SymbolsFile
        @return: A SymbolsFile object initialized from the given breakpad symbols.
        """
        start_time = time.time()
        result = cls()
        result.sym_fp = open(input_file)
        cache_ok = False
        try:
            cache_path = "%s.cache" % input_file
            with open(cache_path) as cache_fp:
                result.files, result.funcs, result.publics = json.load(cache_fp)
            cache_ok = True
        except IOError as exc:
            log.debug("Failed to read ranges cache to %s: %s", cache_path, exc)
        if not cache_ok:
            result.sym_fp.seek(0)
            while True:
                line = result.sym_fp.readline()
                if not line:
                    break
                if not result.files and line.startswith("FILE "):
                    result.files.append(result.sym_fp.tell() - len(line))
                    continue
                if len(result.files) == 1 and not line.startswith("FILE "):
                    result.files.append(result.sym_fp.tell() - len(line))
                if not result.funcs and line.startswith("FUNC "):
                    result.funcs.append(result.sym_fp.tell() - len(line))
                    continue
                if len(result.funcs) == 1 and line.startswith("PUBLIC "):
                    result.funcs.append(result.sym_fp.tell() - len(line))
                if not result.publics and line.startswith("PUBLIC "):
                    result.publics.append(result.sym_fp.tell() - len(line))
                    continue
                if len(result.publics) == 1 and not line.startswith("PUBLIC "):
                    result.publics.append(result.sym_fp.tell() - len(line))
                    break
            if len(result.publics) == 1:
                result.publics.append(result.sym_fp.tell())
        assert len(result.files) == 2
        assert len(result.funcs) == 2
        assert len(result.publics) == 2
        result.files = tuple(result.files)
        result.funcs = tuple(result.funcs)
        result.publics = tuple(result.publics)
        elapsed = time.time() - start_time
        log.debug("Loaded symbols for %s (elapsed %0.1fs%s)",
                  os.path.basename(input_file), elapsed, ", cached" if cache_ok else "")
        log.debug("Got ranges: files %r funcs %r publics %r", result.files, result.funcs, result.publics)
        if not cache_ok:
            try:
                cache_path = "%s.cache" % input_file
                with open(cache_path, "w") as cache_fp:
                    json.dump([result.files, result.funcs, result.publics], cache_fp)
            except IOError as exc:
                log.debug("Failed to write ranges cache to %s: %s", cache_path, exc)
        return result

    def resolve(self, addr):
        """
        Resolve the symbol for an address in the binary represented by this SymbolsFile.

        @type addr: int
        @param addr: Address to resolve.

        @rtype: str or None
        @return: Formatted symbol string for given address, or None on error
        """
        key = lambda line: int(line.split(" ", 2)[1], 16)
        func_pos = bisect_bin(self.sym_fp, addr, prefix="FUNC ", key=key, lo=self.funcs[0], hi=self.funcs[1])
        self.sym_fp.seek(func_pos)
        buf = self.sym_fp.readline().strip()
        log.debug("got line: %s", buf)
        _, func_addr, size, _, name = buf.split(" ", 4)
        func_addr = int(func_addr, 16)
        size = int(size, 16)
        if addr >= (func_addr + size):
            # address isn't in nearest function. return offset from public symbol instead
            pub_pos = bisect_bin(self.sym_fp, addr, prefix="PUBLIC ", key=key, lo=self.publics[0], hi=self.publics[1])
            self.sym_fp.seek(pub_pos)
            buf = self.sym_fp.readline().strip()
            log.debug("got line: %s", buf)
            _, pub_addr, _, name = buf.split(" ", 3)
            pub_addr = int(pub_addr, 16)
            return "%s at 0x%x" % (name, addr - pub_addr)
        line_num = None
        for line in self.sym_fp:
            line_addr, size, line_num, file_num = line.split()
            line_addr = int(line_addr, 16)
            size = int(size, 16)
            if line_addr <= addr < (line_addr + size):
                line_num = int(line_num)
                file_num = int(file_num)
                break
            line_num = None
        if line_num is None:
            raise ValueError
        key = lambda line: int(line.split(" ", 2)[1])
        file_pos = bisect_bin(self.sym_fp, file_num, prefix="FILE ", key=key, lo=self.files[0], hi=self.files[1])
        self.sym_fp.seek(file_pos)
        _, num, file_name = self.sym_fp.readline().strip().split(" ", 2)
        num = int(num)
        assert file_num == num, "looked up %d, got %d" % (file_num, num)
        if file_name.startswith("hg:"):
            # hg:hg.mozilla.org/mozilla-central:obj-firefox/dom/bindings/EventHandlerBinding.cpp:df9a0acc2648
            file_name = file_name.split(":")[2]
        return "%s at %s:%d" % (name, file_name, line_num)


def addr2line(input_log, symbols_path=None):
    """
    Symbolize an input_log using breakpad symbols.

    @type input_log: str
    @param input_log: Crash log to be symbolized.

    @type symbols_path: str
    @param symbols_path: Override the path to search for breakpad symbols. By default will look
                         for a folder named 'symbols' in the same folder as the binary.

    @rtype: str
    @return: Copy of input crash log with symbols resolved if possible.
    """
    start = time.time()
    output = []
    exes = {}
    pos = 0
    for match in re.finditer(r"(?m)^#(?P<frame_num>\d+): \?\?\?\[(?P<exe>.*) \+0x(?P<addr>[a-f0-9]+)\]$", input_log):
        if match.start(0) > pos:
            output.append(input_log[pos:match.start(0)])
        exe, addr = match.group("exe", "addr")
        addr = int(addr, 16)
        if exe not in exes:
            # load symbols for this file
            try:
                exes[exe] = SymbolsFile.from_binary(exe, symbols_path=symbols_path)
            except (AssertionError, IOError) as exc:
                log.info("exception loading symbols for %s: %s", exe, exc)
                exes[exe] = None # insert None so we don't try this exe again
        resolved = None
        if exes.get(exe): # don't use 'in' because exe may have been set to None
            resolved = exes[exe].resolve(addr)
        if resolved:
            output.append("#%s: %s" % (match.group("frame_num"), resolved))
        else:
            output.append(match.group(0))
        pos = match.end(0)
    output.append(input_log[pos:])
    elapsed = time.time() - start
    log.debug("addr2line took %0.2fs", elapsed)
    return "".join(output)


def main():
    """
    Main method for symbolizing a crash dump.

    @rtype: None
    @return: None
    """
    import argparse

    prs = argparse.ArgumentParser()
    prs.add_argument("input_file", help="Input file to symbolize")
    prs.add_argument("-s", "--symbols", help="Override symbol store")
    prs.add_argument("-v", "--verbose", action="store_true", help="Show debugging info")
    args = prs.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    with open(args.input_file) as input_fp:
        sys.stdout.write(addr2line(input_fp.read(), symbols_path=args.symbols))


if __name__ == "__main__":
    logging.basicConfig()
    main()
