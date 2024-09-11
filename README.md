# Le4ked P4ssw0rds

![Le4ked P4ssw0rds Banner](https://pbs.twimg.com/media/GXKcnnOawAA8sw0.jpg)

Le4ked P4ssw0rds is a Python tool designed to search for leaked passwords and check their exposure status. It integrates with the ProxyNova API to find leaks associated with an email and uses the Pwned Passwords API to check for password breaches. Additionally, it ensures Sherlock is installed and available for use.

## Features

    Fetch leaked data related to a given email from ProxyNova.
    Check if passwords have been exposed in known data breaches.
    Save results in JSON or TXT format.
    Display results in a tabular format with breach notifications.
    Automatically checks for and installs Sherlock if not already installed.

## Requirements

    Python 3.x
    pip install -r requirements.txt

## Installation

To ensure that all dependencies are installed, including Sherlock, follow these steps:

    Install Dependencies:

    pip install -r requirements.txt

    Install Sherlock:

    The script will automatically check for and install Sherlock if it is not already installed. You may need root privileges for this step.

## Usage

    Run the Script:

    Execute the script using Python:

    sh

    python leakedpasswords.py

    Input Details:
        Enter the username you want to search for.
        Optionally, provide a proxy (in the format http://proxyserver:port).
        Specify the number of results you want to retrieve (default is 20).

    Save Results:

    After fetching results, you will be prompted to save them. Enter the desired file name with a .json or .txt extension, or choose not to save.

## Notes

    The script will prompt you for root privileges if Sherlock needs to be installed and you do not have it installed already.
    Ensure you have sudo privileges on your system to install Sherlock using apt.
