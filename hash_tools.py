import hashlib
import os
import time
from colorama import Fore, Style, init

init(autoreset=True)

SUPPORTED_HASHES = {
    "1": ("MD5", hashlib.md5),
    "2": ("SHA1", hashlib.sha1),
    "3": ("SHA256", hashlib.sha256),
}

def _hash_word(word, hash_func):
    return hash_func(word.encode()).hexdigest()

def _detect_hash_type(hash_value):
    length_map = {
        32: "1",
        40: "2",
        64: "3",
    }
    return length_map.get(len(hash_value))

def _dictionary_attack(target_hash, hash_func, wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(Fore.RED + "[-] Wordlist not found.")
        return

    start_time = time.time()
    attempts = 0

    print(Fore.CYAN + "[+] Starting dictionary attack...\n")

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                attempts += 1

                computed = _hash_word(word, hash_func)

                if computed == target_hash:
                    elapsed = time.time() - start_time
                    hps = attempts / elapsed if elapsed > 0 else 0

                    print("\n" + Fore.GREEN + "[SUCCESS] Password found!")
                    print(Fore.YELLOW + f"[+] Password: {word}")
                    print(Fore.BLUE + f"[+] Attempts: {attempts}")
                    print(Fore.MAGENTA + f"[+] Time: {elapsed:.2f} sec")
                    print(Fore.CYAN + f"[+] Hashes/sec: {hps:,.2f}")
                    return

                if attempts % 5000 == 0:
                    elapsed = time.time() - start_time
                    hps = attempts / elapsed if elapsed > 0 else 0
                    print(
                        Fore.WHITE +
                        f"[...] Tried: {attempts:,} | "
                        f"H/s: {hps:,.2f}",
                        end="\r"
                    )

        print("\n" + Fore.RED + "[-] Password not found in wordlist.")

    except KeyboardInterrupt:
        print("\n" + Fore.RED + "[!] Attack stopped")

#=========================
# MAIN MENU
#=========================

def run_hash_cracker():
    while True:
        print(Fore.CYAN + "\n==== Hash Dictionary Cracker ====")
        print(Fore.YELLOW + "1) MD5")
        print(Fore.YELLOW + "2) SHA1")
        print(Fore.YELLOW + "3) SHA256")
        print(Fore.YELLOW + "4) Auto-detect")
        print(Fore.RED + "0) Return to Main Menu")

        choice = input(Fore.WHITE + "\nSelect hash type: ").strip()

        if choice == "0":
            break

        if choice == "4":
            target_hash = input("Enter target hash: ").lower()
            detected = _detect_hash_type(target_hash)
            if not detected:
                print(Fore.RED + "[-] Could not detect hash type.")
                continue
            hash_name, hash_func = SUPPORTED_HASHES[detected]
            print(Fore.GREEN + f"[+] Detected {hash_name}")
        elif choice in SUPPORTED_HASHES:
            hash_name, hash_func = SUPPORTED_HASHES[choice]
            target_hash = input("Enter target hash: ").lower()
        else:
            print(Fore.RED + "[-] Invalid choice.")
            continue

        wordlist_path = input("Enter path to wordlist: ").strip()

        print(Fore.BLUE + f"[+] Selected hash: {hash_name}")
        _dictionary_attack(target_hash, hash_func, wordlist_path)
