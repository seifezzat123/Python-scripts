import os

PF = r"D:\forensics cw\Program Files"
PF86 = r"D:\forensics cw\Program Files (x86)"

def list_apps(path):
    apps = []
    if os.path.exists(path):
        for name in os.listdir(path):
            full = os.path.join(path, name)
            if os.path.isdir(full):
                apps.append(name)
    return apps

def main():
    apps = set()

    print("[+] Reading Program Files:", PF)
    apps.update(list_apps(PF))

    print("[+] Reading Program Files (x86):", PF86)
    apps.update(list_apps(PF86))

    print("\n=== INSTALLED APPLICATIONS ===\n")
    for app in sorted(apps):
        print(" -", app)

if __name__ == "__main__":
    main()
