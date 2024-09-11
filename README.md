# Le4ked P4ssw0rds

![Le4ked P4ssw0rds Banner](https://pbs.twimg.com/media/GXKcnnOawAA8sw0.jpg)

Le4ked P4ssw0rds is a Python tool designed to search for leaked passwords and check their exposure status. It integrates with the ProxyNova API to find leaks associated with an email and uses the Pwned Passwords API to check for password breaches.
Features

    Fetch leaked data related to a given email from ProxyNova.
    Check if passwords have been exposed in known data breaches.
    Save results in JSON or TXT format.
    Display results in a tabular format with breach notifications.

Requirements

    Python 3.x
    pip install -r requirements.txt

Usage

    Run the Script

    Execute the script using Python:

    python leakedpasswords.py

    Input Details
        Enter the email or username you want to search for.
        Optionally, provide a proxy (in the format http://proxyserver:port).
        Specify the number of results you want to retrieve (default is 20).

    Save Results

    After fetching results, you will be prompted to save them. Enter the desired file name with .json or .txt extension, or choose not to save.

