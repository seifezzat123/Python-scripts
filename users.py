import os
from Registry import Registry

# --------------------------------------------
# CHANGE THESE TO MATCH YOUR EXTRACTED FILES
# --------------------------------------------
USERS_PATH = r"D:\forensics cw\Users"
SOFTWARE_HIVE = r"D:\forensics cw\SOFTWARE"


# --------------------------------------------
# PART 1 — USER ACCOUNTS (FROM USERS FOLDER)
# --------------------------------------------
def list_user_folders(path):
    users = []

    ignore_profiles = [
        "default", "default user", "all users", "public"
    ]

    for name in os.listdir(path):
        full = os.path.join(path, name)

        if not os.path.isdir(full):
            continue

        # skip system folders
        if name.lower() in ignore_profiles:
            continue

        users.append(name)

    return users


# --------------------------------------------
# PART 2 — SYSTEM REGISTRY INFO (FROM SOFTWARE HIVE)
# --------------------------------------------
def get_registry_info():
    try:
        reg = Registry.Registry(SOFTWARE_HIVE)
    except Exception as e:
        print("[ERROR] Could not open SOFTWARE hive:", e)
        return {}

    try:
        key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
    except Exception:
        print("[ERROR] Could not find Windows CurrentVersion registry key.")
        return {}

    fields = ["ProductName", "EditionID", "CurrentBuild", "RegisteredOwner"]

    info = {}
    for field in fields:
        try:
            info[field] = key.value(field).value()
        except:
            info[field] = "Not Found"

    return info


# --------------------------------------------
# MAIN
# --------------------------------------------
if __name__ == "__main__":

    print("[+] Reading Users folder:", USERS_PATH)
    users = list_user_folders(USERS_PATH)

    print("[+] Reading SOFTWARE hive:", SOFTWARE_HIVE)
    system_info = get_registry_info()

    # ------- OUTPUT -------
    print("\n============================")
    print("   USER ACCOUNTS DETECTED")
    print("============================")
    for user in users:
        print(" -", user)

    print("\n============================")
    print("   SYSTEM REGISTRY INFORMATION")
    print("============================")
    for k, v in system_info.items():
        print(f"{k}: {v}")
