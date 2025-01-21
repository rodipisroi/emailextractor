# EmailExtractor

EmailExtractor is a Python script that analyzes .eml email files. It extracts important information such as IP addresses, URLs, headers, and attachments.

## Features
- IP & URL Extraction: Extracts IP addresses and URLs from email headers and bodies, then defangs them to prevent execution.
- IP Lookup: Performs IP information lookup using the ipinfo.io service.
- Header Extraction: Extracts key email headers such as Subject, From, To, and more.
- Attachment Hashing: Calculates hash values (MD5, SHA1, SHA256) for email attachments.
- Directory Analysis: Can analyze batch email files in a directory at once.

## **Usage**
- First, Install dependencies
  ```sh
  pip install -r requirements.txt
  ```
- Single Email
  ```sh
  python email_analyzer.py -f path/to/email_file.eml
  ```
- Batch Email
  ```sh
  python email_analyzer.py -d path/to/email_directory
  ```


