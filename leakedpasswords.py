#!/usr/bin/python3

import os
import json
import requests
import hashlib
import urllib3
from tabulate import tabulate
from termcolor import colored
import pyfiglet
import shutil
import subprocess
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(
    filename='leaked_passwords.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Constants
DEFAULT_NUMBER_OF_RESULTS = 20
VALID_PROXY_PREFIXES = ('http://', 'https://')

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_terminal_width():
    """Get the current terminal width."""
    return shutil.get_terminal_size().columns

def center_multiline_text(text, width):
    """Center multiline text within the specified width."""
    return "\n".join(line.center(width) for line in text.splitlines())

def is_valid_proxy(proxy):
    """Validate the proxy format and check if it is reachable."""
    if not proxy.startswith(VALID_PROXY_PREFIXES):
        return False
    try:
        response = requests.get(proxy, timeout=5, verify=False)
        return response.status_code == 200
    except requests.RequestException:
        return False

def find_leaks_proxynova(email, proxy=None, number=DEFAULT_NUMBER_OF_RESULTS):
    """
    Fetch leaks from ProxyNova API.

    :param email: The email address to search for.
    :param proxy: Optional proxy for the request.
    :param number: Number of results to return.
    :return: List of results or empty list if an error occurs.
    """
    url = f"https://api.proxynova.com/comb?query={email}"
    headers = {'User-Agent': 'curl'}
    session = requests.Session()
    
    if proxy and is_valid_proxy(proxy):
        session.proxies = {'http': proxy, 'https': proxy}
    elif proxy:
        print(colored("[!] Invalid proxy format or unreachable. Please use a valid http:// or https:// proxy.", "red"))
        return []

    try:
        response = session.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        total_results = data.get("count", 0)
        logging.info(f"Found {total_results} records for {email}")
        return data.get("lines", [])[:number]
    except requests.RequestException as e:
        logging.error(f"Failed to fetch leaks for {email}: {e}")
        print(colored(f"[!] Failed to fetch leaks: {e}", "red"))
        return []

def check_password_breach(password, cache={}):
    """
    Check if a password has been exposed in known breaches.

    :param password: The password to check.
    :param cache: A dictionary to cache results of previously checked passwords.
    :return: Number of times the password has been exposed, or 0 if none.
    """
    if password in cache:
        return cache[password]

    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        hashes = response.text.splitlines()
        for h in hashes:
            h_prefix, count = h.split(':')
            if h_prefix == suffix:
                cache[password] = int(count)
                return int(count)
        cache[password] = 0
        return 0
    except requests.RequestException as e:
        logging.error(f"Error checking password breach for '{password}': {e}")
        print(colored(f"[!] Error checking password breach: {e}", "red"))
        cache[password] = 0
        return 0

def print_results(results, output=None):
    """
    Display and save results in table format.

    :param results: List of results to display.
    :param output: Optional file path to save results.
    """
    headers = ["Username@Domain", "Password"]
    table_data = [line.split(":") for line in results if ":" in line]
    
    if output:
        try:
            if output.endswith('.json'):
                with open(output, 'w') as json_file:
                    json.dump({"lines": results}, json_file, indent=2)
            elif output.endswith('.txt'):
                with open(output, 'w') as txt_file:
                    txt_file.write(tabulate(table_data, headers, showindex="never"))
            else:
                raise ValueError("Unsupported file format. Please use .json or .txt")
            print(colored(f"[+] Data saved in {output}\n", "green"))
            logging.info(f"Results saved to {output}")
        except (IOError, ValueError) as e:
            print(colored(f"[!] Failed to save file: {e}\n", "red"))
            logging.error(f"Failed to save results to {output}: {e}")
    else:
        if table_data:
            print(colored("[+] Results:", "green"))
            print(tabulate(table_data, headers, showindex="never"))
            warned_passwords = set()
            for username, password in table_data:
                breach_count = check_password_breach(password)
                if breach_count and password not in warned_passwords:
                    print(colored(f"[!] Password '{password}' has been exposed {breach_count} times in data breaches.", "red"))
                    warned_passwords.add(password)
        else:
            print(colored("[!] No results to display.", "yellow"))

def run_sherlock(username):
    """
    Run Sherlock to find information about the username.

    :param username: The username to search for.
    """
    try:
        result = subprocess.run(['sherlock', username], capture_output=True, text=True)
        if result.returncode == 0:
            print(colored(result.stdout, "cyan"))
            logging.info(f"Sherlock results for {username}:\n{result.stdout}")
        else:
            print(colored(f"[!] Sherlock returned an error code {result.returncode}.", "red"))
            logging.error(f"Sherlock returned an error code {result.returncode} for username {username}")
    except FileNotFoundError:
        print(colored("[!] Sherlock not found. Please make sure it is installed.", "red"))
    except Exception as e:
        print(colored(f"[!] Error running Sherlock: {e}\n", "red"))
        logging.error(f"Error running Sherlock for username {username}: {e}")

def main():
    """Main function to run the script."""
    clear_screen()
    terminal_width = get_terminal_width()
    figlet_banner = pyfiglet.figlet_format("Le4ked P4ssw0rds", "slant")
    centered_banner = center_multiline_text(figlet_banner, terminal_width)
    print(colored(centered_banner, "yellow"))

    email = input(colored("Enter the username to search: ", "yellow")).strip()
    if not email:
        print(colored("[!] Username cannot be empty!", "red"))
        return

    print(colored("[*] Running Sherlock to find username information...", "cyan"))
    run_sherlock(email)

    proxy = input(colored("Enter proxy (optional): ", "yellow")).strip()
    number_str = input(colored(f"Enter the number of results (default {DEFAULT_NUMBER_OF_RESULTS}): ", "yellow")).strip()
    number = DEFAULT_NUMBER_OF_RESULTS
    if number_str.isdigit():
        number = int(number_str)
    else:
        print(colored(f"[!] Invalid number, defaulting to {DEFAULT_NUMBER_OF_RESULTS}.", "red"))

    results = find_leaks_proxynova(email, proxy, number)
    if results:
        save_output = input(colored("Save results? (yes/no): ", "cyan")).strip().lower()
        if save_output == 'yes':
            output_file = input(colored("Enter output file name (.json or .txt): ", "cyan")).strip()
            if output_file:
                print_results(results, output_file)
            else:
                print(colored("[!] Invalid file name.", "red"))
        else:
            print_results(results)
    else:
        print(colored("[!] No leaks found.\n", "red"))

if __name__ == '__main__':
    main()
