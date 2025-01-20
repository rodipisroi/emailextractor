import os
import re
import sys
import hashlib
import ipaddress
import requests
import email
import argparse

class EmailAnalyzer:
    def __init__(self, file_path=None, directory_path=None):
        self.file_path = file_path
        self.directory_path = directory_path
        self.email_message = None
        if self.file_path:
            self.email_message = self.read_file(self.file_path)

    def read_file(self, file_path):
        """Membaca dan mengurai file email .eml"""
        with open(file_path, 'rb') as file:
            content = file.read()
        parser = email.parser.BytesParser()
        return parser.parsebytes(content)

    def extract_ips(self):
        """Menarik alamat IP dari header dan badan email"""
        ips = set()

        # Extract IP addresses from headers
        for header_name, header_value in self.email_message.items():
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))

        # Extract IP addresses from email body
        for part in self.email_message.walk():
            content_type = part.get_content_type()
            if content_type in ['text/plain', 'text/html']:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='ignore')
                ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))

        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                pass
        return list(set(valid_ips))

    def extract_urls(self):
        """Menarik URL dari badan email"""
        urls = set()
        for part in self.email_message.walk():
            content_type = part.get_content_type()
            if content_type in ['text/plain', 'text/html']:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='ignore')
                urls.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
        return list(urls)

    @staticmethod
    def defang_ip(ip):
        """Membuat IP menjadi defanged (mengganti . menjadi [.]"""
        return ip.replace('.', '[.]')

    @staticmethod
    def defang_url(url):
        """Membuat URL menjadi defanged (mengganti https:// menjadi hxxps[://])"""
        url = url.replace('https://', 'hxxps[://]')
        url = url.replace('.', '[.]')
        return url

    @staticmethod
    def is_reserved_ip(ip):
        """Memeriksa apakah IP termasuk dalam IP yang dibatasi atau privat"""
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ]
        reserved_ranges = [
            '0.0.0.0/8',
            '100.64.0.0/10',
            '169.254.0.0/16',
            '192.0.0.0/24',
            '192.0.2.0/24',
            '198.51.100.0/24',
            '203.0.113.0/24',
            '224.0.0.0/4', 
            '240.0.0.0/4',
        ]
        for r in private_ranges + reserved_ranges:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
                return True
        return False

    def ip_lookup(self, ip):
        """Melakukan lookup informasi IP"""
        if self.is_reserved_ip(ip):
            return None

        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'IP': data.get('ip', ''),
                    'City': data.get('city', ''),
                    'Region': data.get('region', ''),
                    'Country': data.get('country', ''),
                    'Location': data.get('loc', ''),
                    'ISP': data.get('org', ''),
                    'Postal Code': data.get('postal', '')
                }
        except (requests.RequestException, ValueError):
            pass

        return None

    def extract_headers(self):
        """Menarik header yang relevan dari email"""
        headers_to_extract = [
            "Date",
            "Subject",
            "To",
            "From",
            "Reply-To",
            "Return-Path",
            "Message-ID",
            "X-Originating-IP",
            "X-Sender-IP",
            "Authentication-Results"
        ]
        headers = {}
        for key in self.email_message.keys():
            if key in headers_to_extract:
                headers[key] = self.email_message[key]
        return headers

    def extract_attachments(self):
        """Menarik lampiran dan menghitung hash-nya"""
        attachments = []
        for part in self.email_message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            if filename:
                attachments.append({
                    'filename': filename,
                    'md5': hashlib.md5(part.get_payload(decode=True)).hexdigest(),
                    'sha1': hashlib.sha1(part.get_payload(decode=True)).hexdigest(),
                    'sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
                })
        return attachments

    def analyze(self):
        """Melakukan analisis dan mengembalikan hasil dalam bentuk string"""
        result = []
        ips = self.extract_ips()
        urls = self.extract_urls()
        headers = self.extract_headers()
        attachments = self.extract_attachments()

        result.append("Extracted IP Addresses:")
        result.append("====================================")
        for ip in ips:
            defanged_ip = self.defang_ip(ip)
            ip_info = self.ip_lookup(ip)
            if ip_info:
                result.append(f"{defanged_ip} - {ip_info['City']}, {ip_info['Region']}, {ip_info['Country']}, ISP: {ip_info['ISP']}")
            else:
                result.append(defanged_ip)

        result.append("\nExtracted URLs:")
        result.append("====================================")
        for url in urls:
            result.append(self.defang_url(url))

        result.append("\nExtracted Headers:")
        result.append("====================================")
        for key, value in headers.items():
            result.append(f"{key}: {value}")

        result.append("\nExtracted Attachments:")
        result.append("====================================")
        for attachment in attachments:
            result.append(f"Filename: {attachment['filename']}")
            result.append(f"MD5: {attachment['md5']}")
            result.append(f"SHA1: {attachment['sha1']}")
            result.append(f"SHA256: {attachment['sha256']}\n")

        return "\n".join(result)


    def analyze_directory(self):
        """Menganalisis semua email dalam direktori"""
        if not os.path.isdir(self.directory_path):
            print(f"{self.directory_path} is not a valid directory.")
            sys.exit(1)

        print(f"Starting email extraction in directory: {self.directory_path}")
        for filename in os.listdir(self.directory_path):
            if filename.endswith('.eml'):
                file_path = os.path.join(self.directory_path, filename)
                analyzer = EmailAnalyzer(file_path=file_path)
                analysis_result = analyzer.analyze()

                output_file = os.path.join(self.directory_path, f"{os.path.splitext(filename)[0]}-result.txt")
                with open(output_file, 'w') as output:
                    output.write(analysis_result)
                print(f"Analysis result for {filename} saved to {output_file}")

        print("Email extraction completed.")

    def analyze_single_file(self):
        """Menganalisis satu email .eml"""
        if not os.path.isfile(self.file_path):
            print(f"{self.file_path} is not a valid file.")
            sys.exit(1)

        print(f"Starting email extraction for file: {self.file_path}")
        analyzer = EmailAnalyzer(file_path=self.file_path)
        analysis_result = analyzer.analyze()

        output_file = f"{os.path.splitext(self.file_path)[0]}-result.txt"
        with open(output_file, 'w') as output:
            output.write(analysis_result)
        print(f"Analysis result for {self.file_path} saved to {output_file}")
        print("Email extraction completed.")


def main():
    parser = argparse.ArgumentParser(description="Extract IPs, URLs, headers, and attachments from .eml email files.")
    parser.add_argument('-f', '--file', type=str, help='Path to a single .eml file to analyze.')
    parser.add_argument('-d', '--directory', type=str, help='Directory containing .eml files to analyze.')

    args = parser.parse_args()

    if args.file:
        analyzer = EmailAnalyzer(file_path=args.file)
        analyzer.analyze_single_file()
    elif args.directory:
        analyzer = EmailAnalyzer(directory_path=args.directory)
        analyzer.analyze_directory()
    else:
        print("You must specify either a file (-f) or a directory (-d) to analyze.")
        sys.exit(1)


if __name__ == "__main__":
    main()