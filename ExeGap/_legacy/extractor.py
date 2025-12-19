#!/usr/bin/env python3
"""
Simple EXE extractor prototype
- extracts PE resources
- carves common embedded files by signature (ZIP, 7z, RAR, GZ, PE/DLL)
This is a prototype; results are heuristic and may need refinement.
"""
import argparse
import os
import pefile

SIGNATURES = {
    b"PK\x03\x04": ".zip",
    b"MZ": ".exe",
    b"7z\xBC\xAF\x27\x1C": ".7z",
    b"Rar!\x1A\x07\x00": ".rar",
    b"\x1F\x8B\x08": ".gz",
}


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def extract_pe_resources(pe_path, out_dir):
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        print(f"[!] pefile failed to parse PE: {e}")
        return

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print("[-] No resources directory found.")
        return

    res_count = 0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        try:
            if hasattr(entry, 'directory'):
                for res in entry.directory.entries:
                    if hasattr(res, 'directory'):
                        for res_lang in res.directory.entries:
                            data_rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            data = pe.get_data(data_rva, size)
                            name = f"resource_{res_count}.bin"
                            out_path = os.path.join(out_dir, name)
                            with open(out_path, 'wb') as f:
                                f.write(data)
                            res_count += 1
        except Exception:
            continue

    print(f"[+] Extracted {res_count} resource blobs to {out_dir}")


def find_all_offsets(data, sig):
    offs = []
    start = 0
    while True:
        offset = data.find(sig, start)
        if offset == -1:
            break
        offs.append(offset)
        start = offset + 1
    return offs


def carve_by_signatures(data, out_dir):
    ensure_dir(out_dir)
    found = []
    sig_offsets = []
    for sig, ext in SIGNATURES.items():
        offsets = find_all_offsets(data, sig)
        for off in offsets:
            found.append((off, sig, ext))
    
    found.sort(key=lambda x: x[0])
    
    for i, (off, sig, ext) in enumerate(found):
        if i < len(found) - 1:
            size = found[i+1][0] - off
        else:
            size = len(data) - off
        
        out_name = f"carved_{off:08x}{ext}"
        out_path = os.path.join(out_dir, out_name)
        
        with open(out_path, 'wb') as f:
            f.write(data[off:off + size])
        
        print(f"[+] Carved {ext} at offset {off}, size {size} to {out_name}")


def attempt_parse_embedded_pes(data, out_dir):
    ensure_dir(out_dir)
    parsed = 0
    offsets = find_all_offsets(data, b'MZ')
    
    for off in offsets:
        try:
            candidate = data[off:]
            pe = pefile.PE(data=candidate)
            size_est = pe.OPTIONAL_HEADER.SizeOfImage
            
            out_path = os.path.join(out_dir, f"embedded_{off:08x}.exe")
            with open(out_path, 'wb') as f:
                f.write(candidate[:size_est])
            parsed += 1
            print(f"[+] Parsed embedded PE at {off}, wrote {out_path}")
        except Exception:
            continue
    if parsed == 0:
        print("[-] No embedded PE parsed with pefile heuristics.")


def main():
    parser = argparse.ArgumentParser(description='Extract embedded files/resources from an EXE')
    parser.add_argument('exe', help='Path to EXE file')
    parser.add_argument('-o', '--out', default='extracted_out', help='Output directory')
    parser.add_argument('--carve', action='store_true', help='Run signature-based carving')
    parser.add_argument('--resources', action='store_true', help='Extract PE resources')
    parser.add_argument('--parse-embedded-pes', action='store_true', help='Heuristically parse embedded PE/DLLs')
    args = parser.parse_args()

    exe_path = args.exe
    out_dir = args.out
    ensure_dir(out_dir)

    with open(exe_path, 'rb') as f:
        data = f.read()

    if args.resources:
        res_out = os.path.join(out_dir, 'resources')
        ensure_dir(res_out)
        extract_pe_resources(exe_path, res_out)

    if args.carve:
        carve_out = os.path.join(out_dir, 'carved')
        carve_by_signatures(data, carve_out)

    if args.parse_embedded_pes:
        pe_out = os.path.join(out_dir, 'embedded_pe')
        ensure_dir(pe_out)
        attempt_parse_embedded_pes(data, pe_out)

    if not (args.carve or args.resources or args.parse_embedded_pes):
        res_out = os.path.join(out_dir, 'resources')
        ensure_dir(res_out)
        extract_pe_resources(exe_path, res_out)
        carve_out = os.path.join(out_dir, 'carved')
        carve_by_signatures(data, carve_out)
        pe_out = os.path.join(out_dir, 'embedded_pe')
        ensure_dir(pe_out)
        attempt_parse_embedded_pes(data, pe_out)

    print('[+] Done')


if __name__ == '__main__':
    main()
