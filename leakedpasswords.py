#!/usr/bin/python3

import os
import json
import requests
import hashlib
import urllib3
from tabulate import tabulate
from neotermcolor import colored
import pyfiglet  # Importing pyfiglet for banner
import shutil  # For terminal width

urllib3.disable_warnings()

# Function to clear the terminal screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to get terminal width
def get_terminal_width():
    return shutil.get_terminal_size().columns

# Function to center multiline text
def center_multiline_text(text, width):
    return "\n".join(line.center(width) for line in text.splitlines())

# Fetch leaks from ProxyNova API
def find_leaks_proxynova(email, proxy, number):
    url = f"https://api.proxynova.com/comb?query={email}"
    headers = {'User-Agent': 'curl'}
    session = requests.Session()

    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    try:
        response = session.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        total_results = data.get("count", 0)
        print(colored(f"[*] Found {total_results} records", "magenta"))
        return data.get("lines", [])[:number]
    except requests.RequestException as e:
        print(colored(f"[!] Failed to fetch: {e}\n", "red"))
        return []

# Check if a password has been exposed in known breaches
def check_password(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        response.raise_for_status()
        hashes = response.text.splitlines()
        for h in hashes:
            h_prefix, count = h.split(':')
            if h_prefix == suffix:
                return int(count)
    except requests.RequestException as e:
        print(colored(f"[!] Error checking password breach status: {e}\n", "red"))
    return 0

# Display and save results in table format
def print_results(results, output=None):
    headers = ["Username@Domain", "Password"]
    table_data = [line.split(":") for line in results if ":" in line]

    if output:
        try:
            if output.endswith('.json'):
                with open(output, 'w') as json_file:
                    json.dump({"lines": results}, json_file, indent=2)
            else:
                with open(output, 'w') as txt_file:
                    txt_file.write(tabulate(table_data, headers, showindex="never"))
            print(colored(f"[+] Data saved in {output}\n", "green"))
        except IOError as e:
            print(colored(f"[!] Failed to save file: {e}\n", "red"))
    else:
        print(colored("[+] Results:", "green"))
        print(tabulate(table_data, headers, showindex="never"))

        # Check each password for breaches
        for entry in table_data:
            if len(entry) == 2:
                username, password = entry
                breach_count = check_password(password)
                if breach_count:
                    print(colored(f"[!] Password '{password}' has been exposed {breach_count} times in data breaches.", "red"))

# Main function
def main():
    clear_screen()
    terminal_width = get_terminal_width()
    figlet_banner = pyfiglet.figlet_format("Le4ked P4ssw0rds", "slant")
    centered_banner = center_multiline_text(figlet_banner, terminal_width)
    print(colored(centered_banner, "yellow"))

    email = input("Enter the email/user to search: ").strip()
    if not email:
        print(colored("[!] Email/user cannot be empty!", "red"))
        return

    proxy = input("Enter proxy (optional): ").strip()
    number_str = input("Enter the number of results (default 20): ").strip()
    number = 20
    if number_str.isdigit():
        number = int(number_str)

    results = find_leaks_proxynova(email, proxy, number)
    if results:
        save_output = input("Save results? (yes/no): ").strip().lower()
        if save_output == 'yes':
            output_file = input("Enter output file name (.json or .txt): ").strip()
            try:
                print_results(results, output_file)
            except Exception as e:
                print(colored(f"[!] Error saving results: {e}\n", "red"))
        else:
            print_results(results)
    else:
        print(colored("[!] No leaks found.\n", "red"))

if __name__ == '__main__':
    main()
