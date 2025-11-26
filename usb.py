import os
import codecs
from Registry import Registry

SYSTEM_PATH = r"D:\forensics cw\SYSTEM"
NTUSER_ADMIN = r"D:\forensics cw\NTUSER_admin11.DAT"
NTUSER_INFO = r"D:\forensics cw\NTUSER_informant.DAT"

def print_section(title):
    print("\n" + "=" * 50)
    print(f"            {title}")
    print("=" * 50 + "\n")


def print_sub(title):
    print(f"\n--- {title} ---\n")


def parse_usb(reg, control_set):
    print_section(f"USB DEVICES (ControlSet00{control_set})")

    usb_path = f"ControlSet00{control_set}\\Enum\\USB"
    usbstor_path = f"ControlSet00{control_set}\\Enum\\USBSTOR"
    try:
        usb_root = reg.open(usb_path)
        print_sub(usb_path)

        for device in usb_root.subkeys():
            print(f"[Device Class] {device.name()}")

            for instance in device.subkeys():
                print(f"  Instance ID: {instance.name()}")
                for v in instance.values():
                    print(f"     {v.name()}: {v.value()}")
            print()

    except Registry.RegistryKeyNotFoundException:
        print(f"[!] No USB key found in {usb_path}")

    try:
        stor_root = reg.open(usbstor_path)
        print_sub(usbstor_path)

        for device in stor_root.subkeys():
            print(f"[Device Class] {device.name()}")

            for instance in device.subkeys():
                print(f"  Instance ID: {instance.name()}")
                for v in instance.values():
                    print(f"     {v.name()}: {v.value()}")
            print()

    except Registry.RegistryKeyNotFoundException:
        print(f"[!] No USBSTOR key found in {usbstor_path}")


def extract_command_history(user, nt_path):

    print_section(f"COMMAND HISTORY ({user})")

    if not os.path.exists(nt_path):
        print(f"[!] NTUSER not found: {nt_path}")
        return

    reg = Registry.Registry(nt_path)

    print_sub(f"Run Dialog History (RunMRU) for {user}")
    try:
        runmru = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
        for v in runmru.values():
            print(f"{v.name()} = {v.value()}")
    except:
        print("No RunMRU found.")

    print_sub(f"File Explorer Typed Paths for {user}")
    try:
        tp = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
        for v in tp.values():
            print(f"{v.name()} = {v.value()}")
    except:
        print("No TypedPaths found.")


if __name__ == "__main__":
    print_section("USB DEVICE HISTORY")

    reg_sys = Registry.Registry(SYSTEM_PATH)

    for cs in ["1", "2"]:
        parse_usb(reg_sys, cs)

    extract_command_history("admin11", NTUSER_ADMIN)
    extract_command_history("informant", NTUSER_INFO)

    print("\n[+] Completed analysis.\n")
