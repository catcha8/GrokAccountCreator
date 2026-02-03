from curl_cffi import requests
from typing import Dict, Tuple, List
import time
import requests as std_requests
import os
import random
import uuid
from MailTM import Mailjs
import threading
from queue import Queue
import json
from colorama import init as colorama_init
from datetime import datetime

colorama_init()

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'

class Logger:
    _lock = threading.Lock()
    success_count = 0
    fail_count = 0

    @staticmethod
    def _time():
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def _thread():
        return threading.current_thread().name.replace("Thread-", "T")

    @classmethod
    def info(cls, msg):
        with cls._lock:
            print(f"[{cls._time()}] [{cls._thread()}] {msg}")

    @classmethod
    def success(cls, msg):
        with cls._lock:
            cls.success_count += 1
            print(f"[{cls._time()}] [{cls._thread()}] {Colors.GREEN}+{Colors.RESET} {msg}")

    @classmethod
    def error(cls, msg):
        with cls._lock:
            cls.fail_count += 1
            print(f"[{cls._time()}] [{cls._thread()}] {Colors.RED}-{Colors.RESET} {msg}")

    @classmethod
    def warn(cls, msg):
        with cls._lock:
            print(f"[{cls._time()}] [{cls._thread()}] {Colors.YELLOW}!{Colors.RESET} {msg}")

    @classmethod
    def stats(cls):
        with cls._lock:
            total = cls.success_count + cls.fail_count
            print(f"\n{'='*50}")
            print(f"RESULTS | Total: {total} | {Colors.GREEN}Success: {cls.success_count}{Colors.RESET} | {Colors.RED}Failed: {cls.fail_count}{Colors.RESET}")
            print(f"{'='*50}")

class Grok:
    BASE_URL = "https://accounts.x.ai/sign-up"

    def __init__(self, solver_host: str = "localhost", solver_port: int = 5000, solver_api_key: str = "", proxy: str = None, proxy_file: str = None):
        self.session = requests.Session(impersonate="chrome")
        self.authenticated = False
        self.auth_token = None
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        self.proxy = proxy
        self.proxy_pool = []
        self.proxy_file = proxy_file
        self.file_lock = threading.Lock()

        if proxy_file:
            self.load_proxy_pool(proxy_file)
        elif proxy:
            self.proxy_pool = [proxy]

        self.TURNSTILE_SITE_KEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
        self.TURNSTILE_URL = Grok.BASE_URL
        self.mail_client = None
        self.current_proxy = None
        self.SOLVER_HOST = solver_host
        self.SOLVER_PORT = solver_port
        self.SOLVER_API_KEY = solver_api_key

        if solver_api_key == "":
            print("="*50)
            print("Add your APIKEY (Join https://discord.gg/XuGAPnAP45 or https://t.me/NSLSolver for free one)")
            print("="*50)
            os._exit(0)

    def load_proxy_pool(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.proxy_pool.append(line)
            if self.proxy_pool:
                print(f"[INFO] Loaded {len(self.proxy_pool)} proxies")
        except FileNotFoundError:
            print(f"[WARN] Proxy file not found")
        except Exception as e:
            print(f"[ERROR] {str(e)}")

    def get_random_proxy(self) -> Dict[str, str]:
        if not self.proxy_pool:
            return None
        proxy = random.choice(self.proxy_pool)
        return {"http": "http://" + proxy, "https": "http://" + proxy}

    def generate_bnc_uuid(self) -> str:
        return str(uuid.uuid4())

    def get_solver_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json", "X-API-Key": self.SOLVER_API_KEY}

    def get_token(self):
        payload = {
            "type": "turnstile",
            "site_key": self.TURNSTILE_SITE_KEY,
            "url": self.TURNSTILE_URL,
            "user_agent": self.user_agent
        }
        try:
            response = std_requests.post(
                f"http://{self.SOLVER_HOST}:{self.SOLVER_PORT}/solve",
                json=payload,
                headers=self.get_solver_headers(),
                timeout=180
            )
            data = response.json()
            if data.get("success") and data.get("token"):
                token = data.get("token")
                Logger.info(f"Turnstile: {token[:60]}...")
                return token
            return None
        except:
            return None

    def send_verification_email(self, email: str, proxy: Dict[str, str] = None) -> Tuple[bool, str]:
        try:
            headers = {
                'accept': '*/*',
                'accept-language': 'fr-FR,fr;q=0.6',
                'cache-control': 'no-cache',
                'content-type': 'application/grpc-web+proto',
                'origin': 'https://accounts.x.ai',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://accounts.x.ai/sign-up',
                'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Brave";v="144"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
                'x-grpc-web': '1',
                'x-user-agent': 'connect-es/2.1.1',
            }
            email_bytes = email.encode('utf-8')
            email_len = len(email_bytes)
            data = b'\x00\x00\x00\x00' + bytes([email_len + 2]) + b'\x0a' + bytes([email_len]) + email_bytes
            response = requests.post(
                'https://accounts.x.ai/auth_mgmt.AuthManagement/CreateEmailValidationCode',
                headers=headers,
                data=data,
                impersonate="chrome",
                proxies=proxy
            )
            if response.status_code == 200:
                return True, "OK"
            return False, f"Status {response.status_code}"
        except Exception as e:
            return False, str(e)

    def verify_email_code(self, email: str, code: str, proxy: Dict[str, str] = None) -> Tuple[bool, str]:
        try:
            headers = {
                'accept': '*/*',
                'accept-language': 'fr-FR,fr;q=0.6',
                'cache-control': 'no-cache',
                'content-type': 'application/grpc-web+proto',
                'origin': 'https://accounts.x.ai',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://accounts.x.ai/sign-up',
                'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Brave";v="144"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
                'x-grpc-web': '1',
                'x-user-agent': 'connect-es/2.1.1',
            }
            email_bytes = email.encode('utf-8')
            code_bytes = code.encode('utf-8')
            email_len = len(email_bytes)
            code_len = len(code_bytes)
            total_len = 2 + email_len + 2 + code_len
            data = (b'\x00\x00\x00\x00' + bytes([total_len]) +
                   b'\x0a' + bytes([email_len]) + email_bytes +
                   b'\x12' + bytes([code_len]) + code_bytes)
            response = requests.post(
                'https://accounts.x.ai/auth_mgmt.AuthManagement/VerifyEmailValidationCode',
                headers=headers,
                data=data,
                impersonate="chrome",
                proxies=proxy
            )
            if response.status_code == 200:
                return True, "OK"
            return False, f"Status {response.status_code}"
        except Exception as e:
            return False, str(e)

    def get_verification_code(self, mail_client) -> str:
        try:
            if not mail_client:
                return None
            max_attempts = 30
            for attempt in range(max_attempts):
                time.sleep(2)
                messages_result = mail_client.get_messages()
                if messages_result.status and messages_result.data:
                    for msg in messages_result.data:
                        msg_id = msg.get("id")
                        msg_result = mail_client.get_message(msg_id)
                        if msg_result.status:
                            msg_data = msg_result.data
                            return msg_data.get("html")[0].split('Please use the code below to validate your email address.</p>\r\n<table width="100%">\r\n    <tbody>\r\n        <tr>\r\n            <td style="height:15px;"></td>\r\n        </tr>\r\n        <tr>\r\n            <td style="text-align: center; background: #FAFAFA; padding: 30px 20px; font-size: 26px; font-weight: bold;">')[1].split("<")[0]
            return None
        except:
            return None

    def create_account(self, email: str, password: str, first_name: str, last_name: str,
                      verification_code: str, turnstile_token: str, proxy: Dict[str, str] = None) -> Tuple[bool, str, str]:
        try:
            headers = {
                'accept': 'text/x-component',
                'accept-language': 'fr-FR,fr;q=0.6',
                'cache-control': 'no-cache',
                'content-type': 'text/plain;charset=UTF-8',
                'next-action': '7f67aa61adfb0655899002808e1d443935b057c25b',
                'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
                'origin': 'https://accounts.x.ai',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://accounts.x.ai/sign-up?redirect=grok-com',
                'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Brave";v="144"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            data = json.dumps([{
                "emailValidationCode": verification_code,
                "createUserAndSessionRequest": {
                    "email": email,
                    "givenName": first_name,
                    "familyName": last_name,
                    "clearTextPassword": password,
                    "tosAcceptedVersion": 1
                },
                "turnstileToken": turnstile_token,
                "promptOnDuplicateEmail": True
            }, {
                "client": "$T",
                "meta": "$undefined",
                "mutationKey": "$undefined"
            }])
            response = requests.post(
                'https://accounts.x.ai/sign-up?redirect=grok-com',
                headers=headers,
                data=data,
                impersonate="chrome",
                proxies=proxy
            )
            if response.status_code == 200:
                return True, "OK", response.text
            elif response.status_code == 400:
                return False, "Email exists", ""
            elif response.status_code == 429:
                return False, "Rate limited", ""
            return False, f"Status {response.status_code}", ""
        except Exception as e:
            return False, str(e), ""

    def generate_random_name(self) -> Tuple[str, str]:
        first_names = ["John", "Jane", "Mike", "Sarah", "David", "Emily", "Chris", "Lisa", "Alex", "Emma"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
        return random.choice(first_names), random.choice(last_names)

    def generate_random_password(self, length: int = 16) -> str:
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))

    def generate_single_account(self) -> Dict[str, any]:
        mail_client = None
        current_proxy = None
        try:
            if self.proxy_pool:
                current_proxy = self.get_random_proxy()

            proxy_str = ""
            if current_proxy and current_proxy.get("http"):
                proxy_str = current_proxy.get("http").replace("http://", "")

            mail_client = Mailjs(pi_proxie=proxy_str)
            result = mail_client.create_one_account()

            if not result.status:
                return {"success": False, "message": "Temp email failed"}

            email = result.data.get("username")
            Logger.info(f"Email: {email}")

            password = self.generate_random_password()
            first_name, last_name = self.generate_random_name()

            Logger.info("Solving turnstile...")
            turnstile_token = self.get_token()
            if not turnstile_token:
                return {"success": False, "message": "Turnstile failed"}

            Logger.info("Sending verification...")
            success, message = self.send_verification_email(email, current_proxy)
            if not success:
                return {"success": False, "message": f"Send failed: {message}"}

            verification_code = self.get_verification_code(mail_client)
            if not verification_code:
                return {"success": False, "message": "No code received"}
            verification_code = verification_code.replace("-", "").strip()

            Logger.info(f"Code: {verification_code}")

            success, message = self.verify_email_code(email, verification_code, current_proxy)
            if not success:
                Logger.warn(f"Verify failed: {message}")

            Logger.info("Creating account...")
            success, msg, response_text = self.create_account(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                verification_code=verification_code,
                turnstile_token=turnstile_token,
                proxy=current_proxy
            )

            if success:
                return {"success": True, "email": email, "password": password}
            return {"success": False, "message": msg}

        except Exception as e:
            return {"success": False, "message": str(e)}

    def generate_accounts(self, count: int = 1, delay: float = 2.0, output_file: str = "accounts.txt", threads: int = 1) -> Dict[str, List[Dict]]:
        results = {"successful": [], "failed": []}
        results_lock = threading.Lock()
        task_queue = Queue()

        for i in range(1, count + 1):
            task_queue.put(i)

        print(f"\n[GROK GEN] {count} accounts | {threads} threads\n")

        def worker():
            while True:
                try:
                    task_queue.get_nowait()
                except:
                    break

                result = self.generate_single_account()

                with results_lock:
                    if result["success"]:
                        Logger.success(f"{result['email']}")
                        results["successful"].append(result)
                        self.save_account(result, output_file)
                    else:
                        Logger.error(f"{result['message']}")
                        results["failed"].append(result)

                task_queue.task_done()

                if delay > 0:
                    time.sleep(delay)

        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=worker, name=f"Thread-{i+1}")
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        Logger.stats()

        if results['successful']:
            print(f"\nSaved to: {output_file}")

        return results

    def save_account(self, account: Dict, file_path: str = "accounts.txt"):
        try:
            with self.file_lock:
                with open(file_path, 'a', encoding='utf-8') as f:
                    f.write(f"{account['email']}:{account['password']}\n")
        except:
            pass


if __name__ == "__main__":
    generator = Grok(
        solver_host="173.249.41.237",
        solver_port=5000,
        solver_api_key="",
        proxy_file="proxies.txt"
    )

    threads = input("Threads -->")
    results = generator.generate_accounts(count=int(threads), delay=0.01, output_file="accounts.txt", threads=int(threads))