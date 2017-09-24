#!/usr/bin/env python3

import struct, sys, re, datetime
from IPython import embed

from coff import *


u32 = lambda x: struct.unpack('<I', x)[0]
mkpri = lambda c: chr(c) if c < 0x7f and c >= 0x20 else '.'

def parse_debugS(dat):

    vers = u32(dat[:4])

    ptr = 4
    while ptr + 8 < len(dat):
        rectype, reclen = struct.unpack("<II", dat[ptr:][:8])
        if rectype != 0xf1:
            break

        recend = ptr + 8 + reclen
        #print('\nrectype {:x} reclen {:x} ptr {:x}'.format(rectype, reclen, ptr))

        ptr += 8
        while ptr < recend:
            if ptr + 4 > len(dat):
                break
            l, ty = struct.unpack("<HH", dat[ptr:][:4])
            pay = dat[ptr+4:][:l - 2]
            #print(hex(ty), pay)
            ptr += l + 2

        while ptr % 4:
            ptr += 1

def parse_type_record(dat):
    ptr = 0
    while ptr + 4 < len(dat):
        if dat[ptr:][:4] == b'\x02\x15\x03\x00':
            val = struct.unpack('<H', dat[ptr + 4:][:2])[0]
            name = dat[ptr + 4 + 2:]
            name = name[:name.index(b'\x00')]
            #print('(0x{:04x}, {}),'.format(val, name))
            ptr += 4 + 2 + len(name)
        else:
            ptr += 1
            continue

        if dat[ptr] > 0xf0:
            ptr += dat[ptr] & 0xf

def parse_debugT(dat):

    vers = u32(dat[:4])

    ptr = 4
    while ptr + 4 < len(dat):
        if ptr + 4 > len(dat):
            break
        l, ty = struct.unpack("<HH", dat[ptr:][:4])
        pay = dat[ptr+4:][:l - 2]
        #print(hex(ty), pay)
        parse_type_record(pay)
        ptr += l + 2

def parse_obj(dat):
    """
    typedef struct {
      unsigned short f_magic;         /* magic number             */
      unsigned short f_nscns;         /* number of sections       */
      unsigned long  f_timdat;        /* time & date stamp        */
      unsigned long  f_symptr;        /* file pointer to symtab   */
      unsigned long  f_nsyms;         /* number of symtab entries */
      unsigned short f_opthdr;        /* sizeof(optional hdr)     */
      unsigned short f_flags;         /* flags                    */
    } FILHDR;
    """
    f_magic, f_nscns, f_timdat, f_symptr, f_nsyms, \
    f_opthdr, f_flags = struct.unpack("<HHIIIHH", dat[:20])

    secs = []
    syms = []

    ptr = f_symptr
    sym_nr = 0
    while sym_nr < f_nsyms:
        """
        typedef struct {
          union {
            char e_name[E_SYMNMLEN];
            struct {
              unsigned long e_zeroes;
              unsigned long e_offset;
            } e;
          } e;
          unsigned long e_value;
          short e_scnum;
          unsigned short e_type;
          unsigned char e_sclass;
          unsigned char e_numaux;
        } SYMENT;
        """
        e_name, e_value, e_scnum, e_type, e_sclass, e_numaux = \
        struct.unpack("<8sIHHBB", dat[f_symptr + sym_nr * 0x12: f_symptr + (sym_nr + 1) * 0x12])

        ## Take care of not inlined symbols
        if e_name[:4] == b'\x00\x00\x00\x00':
            strtbl = f_symptr + f_nsyms * 0x12
            off = struct.unpack("<I", dat[f_symptr + sym_nr * 0x12 + 4:][:4])[0]
            e_name = dat[strtbl + off:].split(b'\x00')[0]

        e_name = e_name.strip(b'\x00')
        syms.append({'name': e_name, 'value': e_value, 'scnum': e_scnum,
            'type': e_type, 'sclass': e_sclass})
        for i in range(e_numaux):
            syms.append({'name': '', 'value': '', 'scnum': 0, 'type': 0,
                'sclass': 0})

        sym_nr += e_numaux + 1

    ptr = 20
    for s_nr in range(f_nscns):
        """
        typedef struct {
          char           s_name[8];  /* section name                     */
          unsigned long  s_paddr;    /* physical address, aliased s_nlib */
          unsigned long  s_vaddr;    /* virtual address                  */
          unsigned long  s_size;     /* section size                     */
          unsigned long  s_scnptr;   /* file ptr to raw data for section */
          unsigned long  s_relptr;   /* file ptr to relocation           */
          unsigned long  s_lnnoptr;  /* file ptr to line numbers         */
          unsigned short s_nreloc;   /* number of relocation entries     */
          unsigned short s_nlnno;    /* number of line number entries    */
          unsigned long  s_flags;    /* flags                            */
        } SCNHDR;
        """
        s_name, s_paddr, s_vaddr, s_size, s_scnptr, s_relptr, s_lnnoptr, s_nreloc, \
        s_nlnno, s_flags = struct.unpack("<8sIIIIIIHHI", dat[ptr:ptr+0x28])
        payload = dat[s_scnptr:][:s_size]
        relocs = []

        ## Extract relocation information for data and code sections
        if s_flags & 0x60 != 0:
            for r_nr in range(s_nreloc):
                """
                typedef struct {
                  unsigned long  r_vaddr;   /* address of relocation      */
                  unsigned long  r_symndx;  /* symbol we're adjusting for */
                  unsigned short r_type;    /* type of relocation         */
                } RELOC;
                """
                r_vaddr, r_symndx, r_type = \
                struct.unpack("<IIH", dat[s_relptr+r_nr*0x0a:][:0x0a])
                relocs.append({'addr': r_vaddr, 'symidx': r_symndx, 'type':
                    r_type})

        if s_name.decode().strip('\x00') in [".debug$S"]:
            dbg_sym = parse_debugS(payload)
        elif s_name.decode().strip('\x00') in [".debug$T"]:
            dbg_sym = parse_debugT(payload)

        secs.append({'name': s_name, 'type': s_flags, 'raw': payload, 'relocs': relocs})

        ptr += 0x28

    return {'stamp': f_timdat, 'secs': secs, 'syms': syms}

def parse(fname):
    dat = open(fname, 'rb').read()
    res = []

    i = 8
    if dat[:i] != b'!<arch>\n':
        return {'err': -2, 'objs': None}

    names = []
    off = []
    idx = []

    n = 0
    while i < len(dat):
        ## Only extract the most important fields
        name, unk0, unk1, unk2, unk3, stamp, length = map(lambda x: x.decode().strip(),
                [dat[i:i+16], dat[i+16:i+28], dat[i+28:i+34], dat[i+34:i+48],
                    dat[i+34:i+40], dat[i+40:i+48], dat[i+48:i+58]])
        length = int(length, 10)
        try:
            stamp = int(stamp, 10)
        except:
            stamp = 0

        payload = dat[i+60:i+60+length]

        obj = None

        ## i386
        if struct.unpack("<H", payload[:2])[0] == 0x14c:
            obj = parse_obj(payload)
            obj['machine'] = 0x14c
        ## x86-64
        elif struct.unpack("<H", payload[:2])[0] == 0x8664:
            obj = parse_obj(payload)
            obj['machine'] = 0x8664

        # Parse names from linker member (first try)
        if n == 0:
            n_mem = struct.unpack(">I", payload[:4])[0]
            off = list(struct.unpack(">{}I".format(n_mem), payload[4:][:n_mem*4]))

            names = list(map(lambda x: x.decode(),
                payload[4 + n_mem * 4:].split(b'\x00')))

        try:
            if n == 1:
                n_mem = struct.unpack("<I", payload[:4])[0]
                off = list(struct.unpack("<{}I".format(n_mem), payload[4:][:n_mem*4]))
                n_sym = struct.unpack("<I", payload[4+n_mem*4:][:4])[0]
                idx = list(struct.unpack("<{}H".format(n_sym),
                    payload[8+n_mem*4:][:n_sym*2]))

                names = list(map(lambda x: x.decode(),
                    payload[8+n_mem*4+n_sym*2:].split(b'\x00')))
        except:
            pass

            #print(off, idx, names)

        fname = ""
        if i in off:
            fname = names[off.index(i) - 1]
        if n > 1:
            res.append({'name': "{}".format(fname), 'stamp': stamp, 'data': obj})
        i += 58 + 2 + length
        if i % 2: i += 1
        n += 1

    return {'err': 0, 'objs': res}

def err2str(code):
    if code == -2:
        return "AR header not found."
    else:
        return "--- NO ERROR DESCRIPTION ---"


def pprint_hexdump(dmp, prefix = '', truncate = 0x20000):
    trunc = False
    if len(dmp) > truncate:
        trunc = True

    dmp = dmp[:truncate]

    for i in range(len(dmp) // 16):
        print('{:s}{:04x}:   '.format(prefix, i * 16), end = '')
        for j in range(16):
            print('{:02x} '.format(dmp[i * 16 + j]), end = '')
        print(' ' * 3, end = '')
        for j in range(16):
            print(mkpri(dmp[i * 16 + j]), end = '')
        print('')

    i = len(dmp) // 16
    if len(dmp) % 16:
        print('{:s}{:04x}:   '.format(prefix, i * 16), end = '')
        for j in range(len(dmp) % 16):
            print('{:02x} '.format(dmp[i * 16 + j]), end = '')
        print(' ' * 3 * (16 - len(dmp) % 16), end = '')
        print(' ' * 3, end = '')
        for j in range(len(dmp) % 16):
            print(mkpri(dmp[i * 16 + j]), end = '')
        print('')
    if trunc:
        print('{:s}<truncated>'.format(prefix))

def pprint_obj(obj):
    reloc_type = reloc_type_i386 if obj['machine'] == 0x14c else reloc_type_amd64
    for i, sec in enumerate(obj['secs']):

        ty = sec_flags(sec['type'])
        try:
            name = sec['name'].decode().strip('\x00')
        except:
            name = '.decfail'
        print('|')
        print('|- \x1b[33mSection #{:02d}\x1b[39m:    Name {:10s}    ' \
              'Lenght 0x{:03x}'.format(i+1, name, len(sec['raw'])))
        print('|  |- \x1b[31mFlags\x1b[39m:\n|  |     {:s}'.format('|'.join(ty)))

        print('|  |- \x1b[36mRaw data:\x1b[39m')
        pprint_hexdump(sec['raw'], prefix = '|  |     ')
        if len(sec['relocs']) > 0:
            print('|  |- \x1b[34mRelocations\x1b[39m:')
        for r in sec['relocs']:
            print('|  |     Addr 0x{:04x} Symidx 0x{:02x} {:32s} Type {:8s}'.format(
                r['addr'], r['symidx'],
                '({})'.format(obj['syms'][r['symidx']]['name'].decode()),
                reloc_type(r['type'])[0]))

    if len(obj['syms']) > 0:
        print('|')
        print('|- \x1b[32mSymbols\x1b[39m:')
    for i, s in enumerate(obj['syms']):
        if s['name'] == '': continue
        name = s['name'].decode().strip('\x00')
        sec = ''
        if s['scnum'] == 65535:
            sec = 'Absolute Symb.'
        elif s['scnum'] == 65534:
            sec = 'Debug Symb.'
        elif s['scnum'] == 0:
            sec = 'Undefined'
        else:
            sec = "Section {:02d}".format(s['scnum'])

        if i < len(obj['syms']) - 1:
            print('|    {:02x} Name {:32s} Value {:08x} {:14s} {}'.format(i,
                name, s['value'], sec, storage_class(s['sclass'])))
        else:
            print('\'-   {:02x} Name {:32s} Value {:08x} {:14s} {}\n'.format(i, name,
                s['value'], sec, storage_class(s['sclass'])))

def pprint_lib(lib):
    for o in lib['objs']:
        print('\x1b[32m{}\x1b[39m'.format(o['name']), end = '')
        if not o['data']:
            print('')
            continue
        else:
            print(':')
        print('Date: {}    Sections: {}'.format(
            datetime.datetime.fromtimestamp(o['data']['stamp']).strftime('%Y-%m-%d %H:%M:%S'),
            len(o['data']['secs'])))
        pprint_obj(o['data'])

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} <import-/archive-library.lib>".format(sys.argv[0]))
        sys.exit(-1)

    for arg in sys.argv[1:]:
        res = parse(arg)
        if res['err'] < 0:
            print("\x1b[31m[-] " + err2str(res['err']) + "\x1b[39m")
            sys.exit(res['err'])

        pprint_lib(res)
