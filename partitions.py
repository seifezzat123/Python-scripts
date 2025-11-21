import struct

# Only the types you requested
def get_type_description(ptype):
    if ptype == 0x07:
        return "NTFS"
    elif ptype in (0x06, 0x0E):
        return "FAT16"
    elif ptype in (0x01, 0x04, 0x0B, 0x0C):
        return "FAT"
    else:
        return "Unknown"


def parse_partition_entry(entry):
    boot_flag = entry[0]
    part_type = entry[4]
    start_lba = struct.unpack("<I", entry[8:12])[0]
    size_sectors = struct.unpack("<I", entry[12:16])[0]

    return boot_flag, part_type, start_lba, size_sectors


def analyze_mbr(img_path):
    print(f"\nAnalyzing disk image:\n{img_path}\n")

    with open(img_path, "rb") as f:
        mbr = f.read(512)

    # MBR Signature Check
    if mbr[510] != 0x55 or mbr[511] != 0xAA:
        print(" Invalid ")
    else:
        print("Valid.")

    print("\n=== Partition Table Entries ===\n")

    ptable = mbr[446:446 + (16 * 4)]

    for i in range(4):
        entry = ptable[i*16:(i+1)*16]
        boot_flag, part_type, start_lba, size_sectors = parse_partition_entry(entry)

        type_desc = get_type_description(part_type)

        print(f"Partition {i+1}:")
        print(f"  Boot Flag      : {hex(boot_flag)}")
        print(f"  Type (hex)     : {hex(part_type)}")
        print(f"  Type (meaning) : {type_desc}")
        print(f"  Start LBA      : {start_lba}")
        print(f"  Size (sectors) : {size_sectors}")

        # Simple corruption checks
        if part_type != 0x00 and size_sectors == 0:
            print("  Non-zero partition type ")

        if part_type == 0x00 and size_sectors > 0:
            print("  Zero partition type")

        if start_lba == 0 and part_type != 0x00:
            print("  Start LBA = 0")

        print()


if __name__ == "__main__":
    img_path = r"D:\forensics cw\CW Disk Image\CW Image.dd"
    analyze_mbr(img_path)
