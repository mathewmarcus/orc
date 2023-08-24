# ORC (Object Re-Construction)

`orc` is a CLI utility which parses stripped ELF files and attempts to recreate an approximation of the missing section headers

## Background
Since dynamic linking/loading and execution of an ELF binary only requires program headers, the section headers are techincally optional and can be removed.
```bash
$ /bin/busybox id
uid=0(root) gid=0(root)
$ readelf -h /bin/busybox | grep -i section
  Start of section headers:          0 (bytes into file)
  Size of section headers:           0 (bytes)
  Number of section headers:         0
  Section header string table index: 0
$ readelf -S /bin/busybox 

There are no sections in this file.
```

However, many tools (e.g. `objdump` and `gdb`), *depend* on the presence of section headers in order to parse and analyze the target ELF file.

```bash
$ objdump -d /bin/busybox 

/bin/busybox:     file format elf32-tradbigmips

```

```
$ gdb -q /bin/busybox id
0x77f631b0 in ?? ()
(gdb) info functions
All defined functions:
(gdb)
```

## Description

`orc` parses the program headers and segments of a stripped ELF file and attempts to rebuild the section headers.

```bash
$ ./build/orc /bin/busybox 2>/dev/null
$ readelf -h /bin/busybox | grep -i section
  Start of section headers:          329384 (bytes into file)
  Size of section headers:           40 (bytes)
  Number of section headers:         21
  Section header string table index: 20
$ readelf -S /bin/busybox 
There are 21 section headers, starting at offset 0x506a8:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00400134 000134 00001a 00   A  0   0  1
  [ 2] .MIPS.abiflags    MIPS_ABIFLAGS   00400150 000150 000018 00   A  0   0  8
  [ 3] .dynamic          DYNAMIC         00400168 000168 000118 08   A  6   0  4
  [ 4] .hash             HASH            00400280 000280 00095c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          00400bdc 000bdc 0014e0 10   A  6   1  0
  [ 6] .dynstr           STRTAB          004020bc 0020bc 000a79 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          00402b36 002b36 00029c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         00402dd4 002dd4 000050 00   A  6   1  4
  [ 9] .rel.dyn          REL             00402e24 002e24 000048 08   A  5   0  0
  [10] .rel.plt          REL             00402e6c 002e6c 0009d0 08  AI  5  14  0
  [11] .init             PROGBITS        0040383c 00383c 000044 00  AX  0   0  4
  [12] .text             PROGBITS        00403880 003880 03d7b8 00  AX  0   0 16
  [13] .fini             PROGBITS        00441038 041038 00dcc8 00  AX  0   0  4
  [14] .plt              PROGBITS        0044ed00 04ed00 0013c0 00  AX  0   0 32
  [15] .got.plt          PROGBITS        004600d0 0500d0 0004f0 04  WA  0   0  0
  [16] .data             PROGBITS        004605c0 0505c0 00001c 00  WA  0   0 16
  [17] .rld_map          PROGBITS        004605dc 0505dc 000004 00  WA  0   0  4
  [18] .got              PROGBITS        004605e0 0505e0 000008 04 WAp  0   0 16
  [19] .bss              NOBITS          004605f0 0505e8 0006d0 00  WA  0   0 16
  [20] .shstrtab         STRTAB          00000000 050600 0000a8 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
```

Now objdump is able to parse and disassemble the file:
```bash
$ objdump -j .plt -d /bin/busybox | grep -A7 '<getuid@\w*>:'
00450080 <getuid@mips16plt>:
  450080:	b203      	lw	v0,45008c <getuid@mips16plt+0xc>
  450082:	9a60      	lw	v1,0(v0)
  450084:	651a      	move	t8,v0
  450086:	eb00      	jr	v1
  450088:	653b      	move	t9,v1
  45008a:	6500      	nop
  45008c:	0046 05b0 	.word	0x4605b0
```

and `gdb` can properly resolve the symbols

```
$ gdb -q /bin/busybox id
0x77f631b0 in ?? ()
(gdb) info functions getuid@mips
All functions matching regular expression "getuid@mips":

Non-debugging symbols:
0x00450081  getuid@mips16plt
(gdb) break getuid@mips16plt
Breakpoint 1 at 0x450081
(gdb) cont
Continuing.

Breakpoint 1, 0x00450081 in getuid@mips16plt ()
(gdb) x/6i $pc
=> 0x450081 <getuid@mips16plt>:	lw	v0,0x45008c <getuid@mips16plt+11>
   0x450083 <getuid@mips16plt+2>:	lw	v1,0(v0)
   0x450085 <getuid@mips16plt+4>:	move	t8,v0
   0x450087 <getuid@mips16plt+6>:	jr	v1
   0x450089 <getuid@mips16plt+8>:	move	t9,v1
   0x45008b <getuid@mips16plt+10>:	nop
```

## Building
```bash
git clone https://github.com/mathewmarcus/orc.git
mkdir build
cd build/
cmake ..
cmake --build .
```

## Usage
```bash
./orc [ -S section_headers_csv ] [ -s symbols_csv ] elf-file
```

### Positional Arguments
#### elf-file
The ELF file to analyze and to which the section headers will be added. *Note that this file is modified in-place*

### Options
#### -S section_headers_csv
The are some sections which `orc` may not be able to determine automatically. If information (e.g Name, Type, Offset, etc) about these sections is determined by manual reverse-engineering, it can be manually added to a CSV file, which `orc` can then parse. The CSV must *not* include a header file, and each line must match this format - *note that fields correspond to the [fields of a section header](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Section_header)*:

```csv
Name,Type,Addr (hex),Offset (hex),Size,EntSize,Flags,Link,Info,Alignment
```

#### -s symbols_csv
`orc` can optionally generate `.symtab` and `.strtab` sections - which may have be `strip`ed away - if information about these specified is specified via a CSV file. The CSV must match this format:
```csv
"Name","Location","Function Size"
"FUN_00506c44","00506c44","24"
```

Ghidra can be used to create such a CSV file, as described [here](#ghidra-integration)

## Ghidra integration
`orc` includes a [Ghidra script](./scripts/ExportMIPS16Symbols.py) which can be used to generate a CSV containing any/all functions which Ghidra discovers during its analysis of the target ELF.

1. Copy or link the [Ghidra script](./scripts/ExportMIPS16Symbols.py) into one of the Ghidra scripts directories
    ```bash
    $ ln -s `realpath ./scripts/ExportMIPS16Symbols.py` ~/ghidra_scripts/
    ```
2. Open the Ghidra Script Manager window:
3. Click `Refresh Script List`
4. In the left navbar, find and run the MIPS/ExportMIPS16Symbols.py script, which will allow you to specify an output CSV into which the Ghidra-parsed function symbols will be saved.

This CSV file can now be used in the `orc` invocation as described [here](#-s-symbols_csv)

## TODO:
* add support for other architectures/platforms besides MIPS
* support for parsing additional section headers
* code cleanup
* unit tests