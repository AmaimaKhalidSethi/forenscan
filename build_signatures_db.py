"""
ForenScan — Comprehensive Signature Database Builder

Sources:
  - Wikipedia: List of file signatures (https://en.wikipedia.org/wiki/List_of_file_signatures)
  - Gary Kessler's File Signatures Table (https://www.garykessler.net/library/file_sigs.html)
  - FileSignature.org (https://filesignature.org) — 938+ formats reference
  - IANA Media Types registry

Covers 200+ file types across all major categories:
  IMAGE, DOCUMENT, ARCHIVE, EXECUTABLE, SCRIPT, MEDIA, SYSTEM,
  CRYPTO, FORENSIC, FONT, DATABASE, CAD, GIS, GAME, CONTAINER,
  CERTIFICATE, DISK, MOBILE, WEB, EMAIL
"""

import sqlite3
import json
import os
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensic_signatures.db")

# ---------------------------------------------------------------------------
# Master signature table
# Each entry: (name, category, mime_type, header_hex, footer_hex, extensions_json, risk_level)
#
# Risk levels:
#   CRITICAL — polyglot/dropper patterns (e.g. EXE header in image file)
#   HIGH     — executables, scripts, interpreted code
#   MEDIUM   — archives, containers, office macros, disk images
#   LOW      — safe media, documents, fonts, data formats
# ---------------------------------------------------------------------------

SIGNATURES = [

    # ── IMAGES ──────────────────────────────────────────────────────────────
    ("JPEG Image",              "IMAGE",    "image/jpeg",
     "FF D8 FF",               "FF D9",    '["jpg","jpeg","jfif","jpe"]',          "LOW"),

    ("JPEG 2000",               "IMAGE",    "image/jp2",
     "00 00 00 0C 6A 50 20 20","49 45 4E 44",'["jp2","j2k","jpf","jpx","j2c"]',   "LOW"),

    ("PNG Image",               "IMAGE",    "image/png",
     "89 50 4E 47 0D 0A 1A 0A","49 45 4E 44 AE 42 60 82",'["png"]',              "LOW"),

    ("GIF87a Image",            "IMAGE",    "image/gif",
     "47 49 46 38 37 61",      "00 3B",    '["gif"]',                              "LOW"),

    ("GIF89a Image",            "IMAGE",    "image/gif",
     "47 49 46 38 39 61",      "00 3B",    '["gif"]',                              "LOW"),

    ("BMP Bitmap",              "IMAGE",    "image/bmp",
     "42 4D",                  None,       '["bmp","dib"]',                        "LOW"),

    ("TIFF Image (LE)",         "IMAGE",    "image/tiff",
     "49 49 2A 00",            None,       '["tif","tiff"]',                       "LOW"),

    ("TIFF Image (BE)",         "IMAGE",    "image/tiff",
     "4D 4D 00 2A",            None,       '["tif","tiff"]',                       "LOW"),

    ("WebP Image",              "IMAGE",    "image/webp",
     "52 49 46 46",            None,       '["webp"]',                             "LOW"),

    ("ICO Icon",                "IMAGE",    "image/x-icon",
     "00 00 01 00",            None,       '["ico"]',                              "LOW"),

    ("ICNS Apple Icon",         "IMAGE",    "image/icns",
     "69 63 6E 73",            None,       '["icns"]',                             "LOW"),

    ("PSD Photoshop",           "IMAGE",    "image/vnd.adobe.photoshop",
     "38 42 50 53",            None,       '["psd","psb"]',                        "LOW"),

    ("OpenEXR Image",           "IMAGE",    "image/x-exr",
     "76 2F 31 01",            None,       '["exr"]',                              "LOW"),

    ("Canon RAW CR2",           "IMAGE",    "image/x-canon-cr2",
     "49 49 2A 00 10 00 00 00 43 52", None,'["cr2"]',                             "LOW"),

    ("DPX Image",               "IMAGE",    "image/x-dpx",
     "53 44 50 58",            None,       '["dpx"]',                              "LOW"),

    ("Kodak Cineon",            "IMAGE",    "image/x-cineon",
     "80 2A 5F D7",            None,       '["cin"]',                              "LOW"),

    ("FLIF Image",              "IMAGE",    "image/flif",
     "46 4C 49 46",            None,       '["flif"]',                             "LOW"),

    ("BPG Image",               "IMAGE",    "image/bpg",
     "42 50 47 FB",            None,       '["bpg"]',                              "LOW"),

    ("QOI Image",               "IMAGE",    "image/qoi",
     "71 6F 69 66",            None,       '["qoi"]',                              "LOW"),

    ("SVG Image",               "IMAGE",    "image/svg+xml",
     "3C 73 76 67",            None,       '["svg","svgz"]',                       "LOW"),

    ("HEIC Image",              "IMAGE",    "image/heic",
     "66 74 79 70 68 65 69 63",None,       '["heic","heif"]',                      "LOW"),

    ("AVIF Image",              "IMAGE",    "image/avif",
     "66 74 79 70 61 76 69 66",None,       '["avif"]',                             "LOW"),

    ("PCX Image",               "IMAGE",    "image/x-pcx",
     "0A",                     None,       '["pcx"]',                              "LOW"),

    ("TGA Image",               "IMAGE",    "image/x-tga",
     "54 52 55 45 56 49 53 49 4F 4E 2D 58 46 49 4C 45", None, '["tga","icb","vda","vst"]', "LOW"),

    # ── DOCUMENTS ────────────────────────────────────────────────────────────
    ("PDF Document",            "DOCUMENT", "application/pdf",
     "25 50 44 46",            "25 25 45 4F 46",'["pdf"]',                        "LOW"),

    ("OLE2 Compound (DOC/XLS)", "DOCUMENT", "application/msword",
     "D0 CF 11 E0 A1 B1 1A E1",None,      '["doc","xls","ppt","msi","msg","pub","vsd","mpp"]', "MEDIUM"),

    ("DOCX Word",               "DOCUMENT", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "50 4B 03 04",            "50 4B 05 06",'["docx","dotx","docm"]',           "MEDIUM"),

    ("XLSX Excel",              "DOCUMENT", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     "50 4B 03 04",            "50 4B 05 06",'["xlsx","xltx","xlsm"]',           "MEDIUM"),

    ("PPTX PowerPoint",         "DOCUMENT", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
     "50 4B 03 04",            "50 4B 05 06",'["pptx","potx","pptm"]',           "MEDIUM"),

    ("ODT OpenDocument",        "DOCUMENT", "application/vnd.oasis.opendocument.text",
     "50 4B 03 04",            None,       '["odt","ods","odp","odg","odf"]',      "LOW"),

    ("EPUB eBook",              "DOCUMENT", "application/epub+zip",
     "50 4B 03 04",            None,       '["epub"]',                             "LOW"),

    ("PostScript",              "DOCUMENT", "application/postscript",
     "25 21 50 53",            None,       '["ps","eps","ai"]',                    "LOW"),

    ("RTF Document",            "DOCUMENT", "application/rtf",
     "7B 5C 72 74 66",         None,       '["rtf"]',                              "LOW"),

    ("DjVu Document",           "DOCUMENT", "image/vnd.djvu",
     "41 54 26 54 46 4F 52 4D",None,      '["djvu","djv"]',                       "LOW"),

    ("CHM Help",                "DOCUMENT", "application/vnd.ms-htmlhelp",
     "49 54 53 46 03 00 00 00 60 00 00 00", None, '["chm"]',                      "MEDIUM"),

    ("HLP Windows Help",        "DOCUMENT", "application/winhlp",
     "3F 5F",                  None,       '["hlp"]',                              "MEDIUM"),

    ("MOBI eBook",              "DOCUMENT", "application/x-mobipocket-ebook",
     "42 4F 4F 4B 4D 4F 42 49",None,      '["mobi","prc"]',                       "LOW"),

    ("LIT eBook",               "DOCUMENT", "application/x-ms-reader",
     "49 54 4F 4C 49 54 4C 53",None,      '["lit"]',                              "LOW"),

    ("XPS Document",            "DOCUMENT", "application/vnd.ms-xpsdocument",
     "50 4B 03 04",            None,       '["xps","oxps"]',                       "LOW"),

    # ── ARCHIVES ─────────────────────────────────────────────────────────────
    ("ZIP Archive",             "ARCHIVE",  "application/zip",
     "50 4B 03 04",            "50 4B 05 06",'["zip","kmz","maff","msix","nupkg","crx","xpi"]', "MEDIUM"),

    ("RAR 1.50+",               "ARCHIVE",  "application/x-rar-compressed",
     "52 61 72 21 1A 07 00",   None,       '["rar"]',                              "MEDIUM"),

    ("RAR 5.0+",                "ARCHIVE",  "application/x-rar-compressed",
     "52 61 72 21 1A 07 01 00",None,       '["rar"]',                              "MEDIUM"),

    ("7-Zip Archive",           "ARCHIVE",  "application/x-7z-compressed",
     "37 7A BC AF 27 1C",      None,       '["7z"]',                               "MEDIUM"),

    ("GZIP Archive",            "ARCHIVE",  "application/gzip",
     "1F 8B",                  None,       '["gz","tgz","tar.gz"]',                "MEDIUM"),

    ("BZIP2 Archive",           "ARCHIVE",  "application/x-bzip2",
     "42 5A 68",               None,       '["bz2","tbz2","tar.bz2"]',             "MEDIUM"),

    ("XZ Archive",              "ARCHIVE",  "application/x-xz",
     "FD 37 7A 58 5A 00",      None,       '["xz","tar.xz"]',                      "MEDIUM"),

    ("LZ4 Archive",             "ARCHIVE",  "application/x-lz4",
     "04 22 4D 18",            None,       '["lz4"]',                              "MEDIUM"),

    ("Zstandard Archive",       "ARCHIVE",  "application/zstd",
     "28 B5 2F FD",            None,       '["zst","tar.zst"]',                    "MEDIUM"),

    ("LZIP Archive",            "ARCHIVE",  "application/x-lzip",
     "4C 5A 49 50",            None,       '["lz"]',                               "MEDIUM"),

    ("TAR Archive",             "ARCHIVE",  "application/x-tar",
     "75 73 74 61 72",         None,       '["tar"]',                              "MEDIUM"),

    ("Microsoft CAB",           "ARCHIVE",  "application/vnd.ms-cab-compressed",
     "4D 53 43 46",            None,       '["cab"]',                              "MEDIUM"),

    ("CPIO Archive",            "ARCHIVE",  "application/x-cpio",
     "30 37 30 37 30 31",      None,       '["cpio"]',                             "MEDIUM"),

    ("XAR Archive",             "ARCHIVE",  "application/x-xar",
     "78 61 72 21",            None,       '["xar","pkg"]',                        "MEDIUM"),

    ("ARJ Archive",             "ARCHIVE",  "application/x-arj",
     "60 EA",                  None,       '["arj"]',                              "MEDIUM"),

    ("LZH Archive",             "ARCHIVE",  "application/x-lzh-compressed",
     "2D 6C 68 35 2D",         None,       '["lzh","lha"]',                        "MEDIUM"),

    ("StuffIt Archive",         "ARCHIVE",  "application/x-stuffit",
     "53 49 54 21",            None,       '["sit","sitx"]',                       "MEDIUM"),

    ("Debian Package",          "ARCHIVE",  "application/vnd.debian.binary-package",
     "21 3C 61 72 63 68 3E 0A",None,      '["deb"]',                              "MEDIUM"),

    ("RPM Package",             "ARCHIVE",  "application/x-rpm",
     "ED AB EE DB",            None,       '["rpm"]',                              "MEDIUM"),

    ("ISO Disc Image",          "ARCHIVE",  "application/x-iso9660-image",
     "43 44 30 30 31",         None,       '["iso"]',                              "MEDIUM"),

    ("Apple DMG",               "DISK",     "application/x-apple-diskimage",
     "78 01 73 0D 62 62 60",   None,       '["dmg"]',                              "MEDIUM"),

    # ── EXECUTABLES ──────────────────────────────────────────────────────────
    ("Windows PE/EXE",          "EXECUTABLE","application/x-msdownload",
     "4D 5A",                  None,       '["exe","dll","sys","com","ocx","ax","iec","ime","scr","cpl","fon","efi","mui","rs","tsp"]', "HIGH"),

    ("DOS ZM Executable",       "EXECUTABLE","application/x-dosexec",
     "5A 4D",                  None,       '["exe"]',                              "HIGH"),

    ("ELF Binary",              "EXECUTABLE","application/x-elf",
     "7F 45 4C 46",            None,       '["elf","so","ko","out","axf","prx","puff","mod","bin"]', "HIGH"),

    ("Mach-O 32-bit",           "EXECUTABLE","application/x-mach-binary",
     "FE ED FA CE",            None,       '["macho","dylib","o","bundle"]',       "HIGH"),

    ("Mach-O 64-bit",           "EXECUTABLE","application/x-mach-binary",
     "CF FA ED FE",            None,       '["macho","dylib","o","bundle"]',       "HIGH"),

    ("Mach-O Fat Binary",       "EXECUTABLE","application/x-mach-binary",
     "CA FE BA BE",            None,       '["macho","dylib","o","bundle","fat"]',  "HIGH"),

    ("Java Class",              "EXECUTABLE","application/java-vm",
     "CA FE BA BE",            None,       '["class"]',                            "HIGH"),

    ("Dalvik DEX",              "EXECUTABLE","application/x-android-app",
     "64 65 78 0A 30 33 35 00",None,      '["dex"]',                              "HIGH"),

    ("WebAssembly",             "EXECUTABLE","application/wasm",
     "00 61 73 6D",            None,       '["wasm"]',                             "HIGH"),

    ("Flash SWF",               "EXECUTABLE","application/x-shockwave-flash",
     "46 57 53",               None,       '["swf"]',                              "MEDIUM"),

    ("Flash SWF Compressed",    "EXECUTABLE","application/x-shockwave-flash",
     "43 57 53",               None,       '["swf"]',                              "MEDIUM"),

    ("Google CRX Extension",    "EXECUTABLE","application/x-chrome-extension",
     "43 72 32 34",            None,       '["crx"]',                              "HIGH"),

    ("NES ROM",                 "GAME",     "application/x-nintendo-nes-rom",
     "4E 45 53 1A",            None,       '["nes"]',                              "MEDIUM"),

    ("VMDK Disk Image",         "DISK",     "application/x-vmdk",
     "4B 44 4D",               None,       '["vmdk"]',                             "MEDIUM"),

    # ── SCRIPTS ──────────────────────────────────────────────────────────────
    ("Shell Script",            "SCRIPT",   "application/x-sh",
     "23 21",                  None,       '["sh","bash","zsh","ksh","csh","tcsh","fish"]', "HIGH"),

    ("Python Bytecode 3.x",     "SCRIPT",   "application/x-python-bytecode",
     "0D 0D 0A",               None,       '["pyc","pyo"]',                        "HIGH"),

    ("Python Bytecode 2.x",     "SCRIPT",   "application/x-python-bytecode",
     "D1 F2 D8 0D",            None,       '["pyc"]',                              "HIGH"),

    ("Windows Script",          "SCRIPT",   "application/x-wsh",
     "57 69 6E 64 6F 77 73 20 53 63", None,'["wsh","wsf"]',                       "HIGH"),

    ("Lua Bytecode",            "SCRIPT",   "application/x-lua-bytecode",
     "1B 4C 75 61",            None,       '["luac"]',                             "HIGH"),

    ("Ruby Script",             "SCRIPT",   "text/x-ruby",
     "23 21 2F",               None,       '["rb"]',                               "HIGH"),

    ("Perl Script",             "SCRIPT",   "text/x-perl",
     "23 21 2F",               None,       '["pl","pm"]',                          "HIGH"),

    ("PHP Script",              "SCRIPT",   "application/x-httpd-php",
     "3C 3F 70 68 70",         None,       '["php","php3","php4","php5","phtml"]', "HIGH"),

    ("PowerShell Script",       "SCRIPT",   "application/x-powershell",
     "23 20",                  None,       '["ps1","psm1","psd1"]',                "HIGH"),

    ("AutoHotkey Script",       "SCRIPT",   "text/x-autohotkey",
     "3B 20 3C 47 55 49 44 3E",None,      '["ahk"]',                              "HIGH"),

    # ── MEDIA — AUDIO ────────────────────────────────────────────────────────
    ("MP3 Audio (ID3v2)",       "MEDIA",    "audio/mpeg",
     "49 44 33",               None,       '["mp3"]',                              "LOW"),

    ("MP3 Audio",               "MEDIA",    "audio/mpeg",
     "FF FB",                  None,       '["mp3"]',                              "LOW"),

    ("WAV Audio",               "MEDIA",    "audio/wav",
     "52 49 46 46",            None,       '["wav"]',                              "LOW"),

    ("FLAC Audio",              "MEDIA",    "audio/flac",
     "66 4C 61 43",            None,       '["flac"]',                             "LOW"),

    ("OGG Container",           "MEDIA",    "audio/ogg",
     "4F 67 67 53",            None,       '["ogg","oga","ogv","ogx","opus"]',     "LOW"),

    ("MIDI",                    "MEDIA",    "audio/midi",
     "4D 54 68 64",            None,       '["mid","midi"]',                       "LOW"),

    ("AAC Audio",               "MEDIA",    "audio/aac",
     "FF F1",                  None,       '["aac","adts"]',                       "LOW"),

    ("AIFF Audio",              "MEDIA",    "audio/aiff",
     "46 4F 52 4D",            None,       '["aiff","aif","aifc"]',                "LOW"),

    ("WMA Audio",               "MEDIA",    "audio/x-ms-wma",
     "30 26 B2 75 8E 66 CF 11",None,      '["wma","wmv","asf"]',                  "LOW"),

    ("M4A Audio",               "MEDIA",    "audio/mp4",
     "66 74 79 70 4D 34 41 20",None,      '["m4a","m4b","m4r"]',                  "LOW"),

    # ── MEDIA — VIDEO ────────────────────────────────────────────────────────
    ("MP4 Video",               "MEDIA",    "video/mp4",
     "66 74 79 70",            None,       '["mp4","m4v","mov","3gp","3g2","f4v","f4p","f4a","f4b"]', "LOW"),

    ("AVI Video",               "MEDIA",    "video/x-msvideo",
     "52 49 46 46",            None,       '["avi"]',                              "LOW"),

    ("MKV / WebM",              "MEDIA",    "video/x-matroska",
     "1A 45 DF A3",            None,       '["mkv","mka","mks","mk3d","webm"]',    "LOW"),

    ("FLV Video",               "MEDIA",    "video/x-flv",
     "46 4C 56 01",            None,       '["flv"]',                              "LOW"),

    ("MPEG Video",              "MEDIA",    "video/mpeg",
     "00 00 01 BA",            None,       '["mpg","mpeg","vob"]',                 "LOW"),

    ("MPEG Transport Stream",   "MEDIA",    "video/mp2t",
     "47",                     None,       '["ts","mts","m2ts"]',                  "LOW"),

    ("WMV Video",               "MEDIA",    "video/x-ms-wmv",
     "30 26 B2 75 8E 66 CF 11",None,      '["wmv","asf"]',                        "LOW"),

    ("Real Video",              "MEDIA",    "video/x-realmedia",
     "2E 52 4D 46",            None,       '["rm","rmvb","ra"]',                   "LOW"),

    # ── SYSTEM / DATABASE ────────────────────────────────────────────────────
    ("SQLite Database",         "DATABASE", "application/x-sqlite3",
     "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", None,
     '["db","sqlite","sqlite3","sqlitedb","db3","s3db","sl3"]',                    "MEDIUM"),

    ("Microsoft Access DB",     "DATABASE", "application/x-msaccess",
     "00 01 00 00 53 74 61 6E",None,      '["mdb","accdb"]',                      "MEDIUM"),

    ("HDF5 Data",               "DATABASE", "application/x-hdf",
     "89 48 44 46 0D 0A 1A 0A",None,      '["hdf5","h5","hdf","he5"]',            "LOW"),

    ("Paradox DB",              "DATABASE", "application/x-paradox",
     "03 00 00 00",            None,       '["db"]',                               "MEDIUM"),

    # ── CERTIFICATES / CRYPTO ────────────────────────────────────────────────
    ("PEM Certificate",         "CRYPTO",   "application/x-pem-file",
     "2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 2D 2D 2D 2D 2D", None,
     '["pem","crt","cer"]',                                                        "MEDIUM"),

    ("PEM Private Key",         "CRYPTO",   "application/x-pem-file",
     "2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", None,
     '["pem","key"]',                                                              "HIGH"),

    ("PEM RSA Key",             "CRYPTO",   "application/x-pem-file",
     "2D 2D 2D 2D 2D 42 45 47 49 4E 20 52 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", None,
     '["pem","key"]',                                                              "HIGH"),

    ("DER Certificate",         "CRYPTO",   "application/x-x509-ca-cert",
     "30 82",                  None,       '["der","cer","crt"]',                  "MEDIUM"),

    ("PFX/PKCS12",              "CRYPTO",   "application/x-pkcs12",
     "30 82",                  None,       '["pfx","p12"]',                        "HIGH"),

    ("GPG/PGP Armored",         "CRYPTO",   "application/pgp-encrypted",
     "2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 47 50", None,
     '["asc","gpg","pgp"]',                                                        "MEDIUM"),

    ("GPG Binary",              "CRYPTO",   "application/pgp-encrypted",
     "99 01",                  None,       '["gpg","pgp"]',                        "MEDIUM"),

    ("PuTTY Key v2",            "CRYPTO",   "application/x-putty-private-key",
     "50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 32 3A", None,
     '["ppk"]',                                                                    "HIGH"),

    ("PuTTY Key v3",            "CRYPTO",   "application/x-putty-private-key",
     "50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 33 3A", None,
     '["ppk"]',                                                                    "HIGH"),

    # ── FORENSICS / NETWORK CAPTURES ────────────────────────────────────────
    ("PCAP Network Capture",    "FORENSIC", "application/vnd.tcpdump.pcap",
     "D4 C3 B2 A1",            None,       '["pcap","cap"]',                       "MEDIUM"),

    ("PCAP Big-Endian",         "FORENSIC", "application/vnd.tcpdump.pcap",
     "A1 B2 C3 D4",            None,       '["pcap","cap"]',                       "MEDIUM"),

    ("PCAPng Capture",          "FORENSIC", "application/vnd.tcpdump.pcap",
     "0A 0D 0D 0A",            None,       '["pcapng","pcap"]',                    "MEDIUM"),

    ("Windows Event Log",       "FORENSIC", "application/x-ms-evtx",
     "45 6C 66 46 69 6C 65 00",None,      '["evtx"]',                             "MEDIUM"),

    ("Windows Registry Hive",   "FORENSIC", "application/x-windows-registry",
     "72 65 67 66",            None,       '["dat","hiv","ntuser"]',               "MEDIUM"),

    ("Prefetch File",           "FORENSIC", "application/x-windows-prefetch",
     "4D 41 4D 04",            None,       '["pf"]',                               "MEDIUM"),

    ("Windows LNK Shortcut",    "FORENSIC", "application/x-ms-shortcut",
     "4C 00 00 00 01 14 02 00",None,      '["lnk"]',                              "HIGH"),

    ("DICOM Medical",           "FORENSIC", "application/dicom",
     "44 49 43 4D",            None,       '["dcm","dicom"]',                      "LOW"),

    ("Thumbs.db",               "FORENSIC", "application/x-thumbs-db",
     "D0 CF 11 E0 A1 B1 1A E1",None,      '["db"]',                               "MEDIUM"),

    ("Pagefile / Hibernation",  "FORENSIC", "application/x-windows-pagefile",
     "50 41 47 45 46 49 4C 45",None,      '["sys"]',                              "MEDIUM"),

    ("Recycle Bin INFO2",       "FORENSIC", "application/x-windows-recycle-bin",
     "05 00 00 00",            None,       '["dat"]',                              "MEDIUM"),

    # ── FONTS ────────────────────────────────────────────────────────────────
    ("TrueType Font",           "FONT",     "font/ttf",
     "00 01 00 00",            None,       '["ttf","ttc"]',                        "LOW"),

    ("OpenType Font",           "FONT",     "font/otf",
     "4F 54 54 4F",            None,       '["otf"]',                              "LOW"),

    ("WOFF Font",               "FONT",     "font/woff",
     "77 4F 46 46",            None,       '["woff"]',                             "LOW"),

    ("WOFF2 Font",              "FONT",     "font/woff2",
     "77 4F 46 32",            None,       '["woff2"]',                            "LOW"),

    # ── WEB / DATA ───────────────────────────────────────────────────────────
    ("XML Document",            "DOCUMENT", "application/xml",
     "3C 3F 78 6D 6C 20",      None,       '["xml","xsl","xslt","xsd","rss","atom","svg"]', "LOW"),

    ("HTML Document",           "WEB",      "text/html",
     "3C 68 74 6D 6C",         None,       '["html","htm","xhtml"]',               "LOW"),

    ("HTML DOCTYPE",            "WEB",      "text/html",
     "3C 21 44 4F 43 54 59 50 45", None,  '["html","htm"]',                       "LOW"),

    ("JSON Data",               "DOCUMENT", "application/json",
     "7B 0A",                  None,       '["json"]',                             "LOW"),

    ("JavaScript",              "SCRIPT",   "application/javascript",
     "2F 2F",                  None,       '["js","mjs","cjs"]',                   "MEDIUM"),

    ("CSS Stylesheet",          "WEB",      "text/css",
     "2F 2A",                  None,       '["css"]',                              "LOW"),

    # ── EMAIL ────────────────────────────────────────────────────────────────
    ("Outlook MSG",             "EMAIL",    "application/vnd.ms-outlook",
     "D0 CF 11 E0 A1 B1 1A E1",None,      '["msg"]',                              "MEDIUM"),

    ("EML Email",               "EMAIL",    "message/rfc822",
     "52 65 74 75 72 6E 2D 50 61 74 68", None, '["eml","mht"]',                   "LOW"),

    ("MBOX Mailbox",            "EMAIL",    "application/mbox",
     "46 72 6F 6D 20",         None,       '["mbox","mbx"]',                       "LOW"),

    ("PST Outlook Data",        "EMAIL",    "application/vnd.ms-outlook-pst",
     "21 42 44 4E",            None,       '["pst","ost","nst"]',                  "MEDIUM"),

    # ── CAD / GIS ────────────────────────────────────────────────────────────
    ("AutoCAD DWG",             "CAD",      "image/vnd.dwg",
     "41 43 31 30",            None,       '["dwg"]',                              "LOW"),

    ("AutoCAD DXF",             "CAD",      "image/vnd.dxf",
     "30 0D 0A",               None,       '["dxf"]',                              "LOW"),

    ("ESRI Shapefile",          "GIS",      "application/x-esri-shape",
     "00 00 27 0A",            None,       '["shp"]',                              "LOW"),

    # ── DISK IMAGES ──────────────────────────────────────────────────────────
    ("VirtualBox VDI",          "DISK",     "application/x-virtualbox-vdi",
     "3C 3C 3C 20 4F 72 61 63 6C 65 20 56 4D 20 56 69 72 74 75 61 6C 42 6F 78 20 44 69 73 6B 20 49 6D 61 67 65 20 3E 3E 3E", None,
     '["vdi"]',                                                                    "MEDIUM"),

    ("VMDK Virtual Disk",       "DISK",     "application/x-vmdk",
     "4B 44 4D",               None,       '["vmdk"]',                             "MEDIUM"),

    ("VHD Virtual Hard Disk",   "DISK",     "application/x-vhd",
     "63 6F 6E 65 63 74 69 78",None,      '["vhd","avhd"]',                       "MEDIUM"),

    # ── MOBILE ───────────────────────────────────────────────────────────────
    ("Android APK",             "MOBILE",   "application/vnd.android.package-archive",
     "50 4B 03 04",            None,       '["apk","aab"]',                        "HIGH"),

    ("iOS IPA",                 "MOBILE",   "application/x-ios-app",
     "50 4B 03 04",            None,       '["ipa"]',                              "HIGH"),

    ("Android OAT",             "MOBILE",   "application/x-android-oat",
     "7F 45 4C 46",            None,       '["oat","odex"]',                       "HIGH"),

    # ── CONTAINER / PACKAGE MANAGERS ────────────────────────────────────────
    ("WASM Module",             "CONTAINER","application/wasm",
     "00 61 73 6D",            None,       '["wasm"]',                             "HIGH"),

    ("JAR Java Archive",        "CONTAINER","application/java-archive",
     "50 4B 03 04",            None,       '["jar","war","ear","aar"]',            "HIGH"),

    ("NUGET Package",           "CONTAINER","application/zip",
     "50 4B 03 04",            None,       '["nupkg"]',                            "MEDIUM"),

    # ── TEXT / ENCODING BOM ──────────────────────────────────────────────────
    ("UTF-8 BOM Text",          "DOCUMENT", "text/plain",
     "EF BB BF",               None,       '["txt","csv","log","md","rst"]',       "LOW"),

    ("UTF-16 LE BOM",           "DOCUMENT", "text/plain",
     "FF FE",                  None,       '["txt","log"]',                        "LOW"),

    ("UTF-16 BE BOM",           "DOCUMENT", "text/plain",
     "FE FF",                  None,       '["txt","log"]',                        "LOW"),

    ("UTF-32 LE BOM",           "DOCUMENT", "text/plain",
     "FF FE 00 00",            None,       '["txt"]',                              "LOW"),

    # ── SYSTEM / FIRMWARE ────────────────────────────────────────────────────
    ("Windows Registry",        "SYSTEM",   "application/x-windows-registry",
     "52 45 47 45 44 49 54",   None,       '["reg"]',                              "HIGH"),

    ("Windows Event Log (old)", "SYSTEM",   "application/x-ms-evtx",
     "30 00 00 00 4C 66 4C 65",None,      '["evt"]',                              "MEDIUM"),

    ("Windows Crash Dump",      "SYSTEM",   "application/x-windows-dump",
     "50 41 47 45 44 55 36 34",None,      '["dmp","mdmp"]',                       "MEDIUM"),

    ("Windows Minidump",        "SYSTEM",   "application/x-windows-dump",
     "4D 44 4D 50 93 A7",      None,      '["mdmp","dmp"]',                       "MEDIUM"),

    ("Windows Thumbnail Cache", "SYSTEM",   "application/x-ms-thumbsdb",
     "43 4D 4D 4D",            None,       '["db"]',                               "LOW"),

    ("Java KeyStore",           "SYSTEM",   "application/x-java-keystore",
     "FE ED FE ED",            None,       '["jks","keystore"]',                   "MEDIUM"),

    ("Linux EXT2/3/4 FS",       "SYSTEM",   "application/x-ext4",
     "53 EF",                  None,       '["img","bin"]',                        "MEDIUM"),

    ("FIT GPS Data",            "SYSTEM",   "application/x-garmin-fit",
     "0E 10 D9 07",            None,       '["fit"]',                              "LOW"),

    ("FITS Astronomy",          "SYSTEM",   "application/fits",
     "53 49 4D 50 4C 45",      None,       '["fits","fit","fts"]',                 "LOW"),

    # ── 3D / CAD ────────────────────────────────────────────────────────────
    ("Blender 3D",              "CAD",      "application/x-blender",
     "42 4C 45 4E 44 45 52",   None,       '["blend"]',                            "LOW"),

    ("STL Binary 3D",           "CAD",      "application/sla",
     "73 6F 6C 69 64",         None,       '["stl"]',                              "LOW"),

    ("COLLADA 3D",              "CAD",      "model/vnd.collada+xml",
     "3C 3F 78 6D 6C",         None,       '["dae"]',                              "LOW"),

    ("glTF Binary",             "CAD",      "model/gltf-binary",
     "67 6C 54 46",            None,       '["glb"]',                              "LOW"),

    # ── GAME FORMATS ─────────────────────────────────────────────────────────
    ("Unity Asset",             "GAME",     "application/x-unity-asset",
     "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 14", None, '["assets"]',        "MEDIUM"),

    ("WAD Game Archive",        "GAME",     "application/x-doom-wad",
     "49 57 41 44",            None,       '["wad"]',                              "MEDIUM"),

    ("PWAD Game Archive",       "GAME",     "application/x-doom-wad",
     "50 57 41 44",            None,       '["wad"]',                              "MEDIUM"),

    # ── MALWARE INDICATORS (CRITICAL) ────────────────────────────────────────
    ("PE in JPEG (Polyglot)",   "EXECUTABLE","application/x-msdownload",
     "FF D8 FF",               None,       '["jpg","jpeg"]',                       "CRITICAL"),

    ("PE in PDF (Polyglot)",    "EXECUTABLE","application/x-msdownload",
     "25 50 44 46",            None,       '["pdf"]',                              "CRITICAL"),

    ("PE in PNG (Polyglot)",    "EXECUTABLE","application/x-msdownload",
     "89 50 4E 47",            None,       '["png"]',                              "CRITICAL"),

    ("PE in ZIP (Polyglot)",    "EXECUTABLE","application/x-msdownload",
     "50 4B 03 04",            None,       '["zip","docx","xlsx"]',                "CRITICAL"),

    # ── ADDITIONAL COMMON FORMATS ────────────────────────────────────────────
    ("Apple Binary plist",      "SYSTEM",   "application/x-bplist",
     "62 70 6C 69 73 74",      None,       '["plist"]',                            "LOW"),

    ("Telegram Desktop",        "SYSTEM",   "application/x-telegram-desktop",
     "54 44 46 24",            None,       '["tdf"]',                              "LOW"),

    ("Telegram Encrypted",      "SYSTEM",   "application/x-telegram-desktop",
     "54 44 45 46",            None,       '["tdef"]',                             "MEDIUM"),

    ("Password Gorilla DB",     "CRYPTO",   "application/x-password-safe",
     "50 57 53 33",            None,       '["psafe3","dat"]',                     "MEDIUM"),

    ("KeePass DB v1",           "CRYPTO",   "application/x-keepass",
     "03 D9 A2 9A 65 FB 4B B5",None,      '["kdb"]',                              "MEDIUM"),

    ("KeePass DB v2",           "CRYPTO",   "application/x-keepass",
     "03 D9 A2 9A 67 FB 4B B5",None,      '["kdbx"]',                             "MEDIUM"),

    ("LZFSE Compressed",        "ARCHIVE",  "application/x-lzfse",
     "62 76 78 32",            None,       '["lzfse"]',                            "MEDIUM"),

    ("OpenSSH Key",             "CRYPTO",   "application/x-openssh-key",
     "2D 2D 2D 2D 2D 42 45 47 49 4E 20 4F 50 45 4E 53 53 48 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", None,
     '["key","pem"]',                                                              "HIGH"),

    ("RIFF Container",          "MEDIA",    "application/x-riff",
     "52 49 46 46",            None,       '["riff","avi","wav","webp","avi"]',     "LOW"),
]


def build_database(db_path: str = DB_PATH) -> None:
    print(f"Building signature database: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")

    # Wipe existing signatures (keep scan_results)
    conn.execute("DELETE FROM signatures")
    conn.commit()

    inserted = 0
    skipped = 0

    for row in SIGNATURES:
        name, cat, mime, header, footer, exts, risk = row
        try:
            conn.execute(
                "INSERT INTO signatures (name,category,mime_type,header_hex,footer_hex,extensions,risk_level)"
                " VALUES (?,?,?,?,?,?,?)",
                (name, cat, mime, header, footer, exts, risk)
            )
            inserted += 1
        except Exception as e:
            print(f"  SKIP {name}: {e}")
            skipped += 1

    conn.commit()
    conn.close()

    print(f"Done. Inserted: {inserted}  Skipped: {skipped}")
    print(f"Total signatures: {inserted}")

    # Category breakdown
    conn2 = sqlite3.connect(db_path)
    rows = conn2.execute(
        "SELECT category, COUNT(*) as n FROM signatures GROUP BY category ORDER BY n DESC"
    ).fetchall()
    print("\nCategory breakdown:")
    for cat, count in rows:
        print(f"  {cat:<16} {count:>4}")
    conn2.close()


if __name__ == "__main__":
    build_database()