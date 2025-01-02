# SQLI_TOOL

An advanced SQL Injection Scanner that allows you to test URLs for SQL injection vulnerabilities using different payloads.

## Features
- Scan a single URL or a list of URLs from a file.
- Customize the number of threads for faster scanning.
- Use predefined or custom payloads to test for vulnerabilities.
- Supports verbose output and timeout customization.

## Installation

To install the required dependencies, use the following command:

```bash
pip install -r requirements.txt
```

## Usage

python sqli_scanner.py -u <URL> -p <path_to_payloads_file> [-t THREADS] [-v] [--timeout TIMEOUT]


To add a README to your project, follow these steps:
Step 1: Create a README.md file

In the project folder, create a new file called README.md. You can open it in a text editor (such as VSCode or Notepad) and add the following content:

# SQLI_TOOL

An advanced SQL Injection Scanner that allows you to test URLs for SQL injection vulnerabilities using different payloads.

## Features
- Scan a single URL or a list of URLs from a file.
- Customize the number of threads for faster scanning.
- Use predefined or custom payloads to test for vulnerabilities.
- Supports verbose output and timeout customization.

## Installation

To install the required dependencies, use the following command:

```bash
pip install -r requirements.txt
```

Usage

To run the scanner:
```bash
python sqli_scanner.py -u <URL> -p <path_to_payloads_file> [-t THREADS] [-v] [--timeout TIMEOUT]
```
Options:

    -h, --help Show help message and exit
    -u, --url URL Single URL to scan
    -f, --file FILE File containing URLs to scan
    -p, --payloads PAYLOADS Path to payload file
    -t, --threads THREADS Number of threads
    -v, --verbose Enable verbose output
    --timeout TIMEOUT Request timeout in seconds
  ## Example
    ```bash
    python sqli_scanner.py -u http://example.com -p payloads.txt
     ```
   Scan URLs from a file:

     python sqli_scanner.py -f urls.txt -p payloads.txt -t 4 -v

     License

This project is licensed under the MIT License - see the LICENSE file for details.

   
