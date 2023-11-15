import re
import hashlib
import requests
from requests_ntlm import HttpNtlmAuth
from secret_servers.nodes_list import NodesList

from utils.utils import Utils
from utils.sscrawl_logger import SSCrawlLogger
from secret_servers.secret_server_node import SSNode
from secret_servers.secret_server import SecretServer
from secret_servers.secret_server import SecretListItem

AUTH_PATH = "/oauth2/token"
API_PATH = "/api"
SECRETS_PATH = "/v1/secrets"
AUTHENTICATION_METHOD_BEARER = 'bearer'
AUTHENTICATION_METHOD_NTLM = 'ntlm'
NTLM_PATH = '/winauthwebservices'


class ThycoticSecretServer(SecretServer):
    def __init__(self, logger: SSCrawlLogger, url: str, page_size: int):
        super().__init__(logger, url)
        self.page_size = page_size
        self.authentication_methods = [AUTHENTICATION_METHOD_BEARER, AUTHENTICATION_METHOD_NTLM]

    def connect_session(self, domain: str, username: str, password: str,
                        session: requests.Session, authentication_method: str, is_hash: bool) -> bool:
        if authentication_method != AUTHENTICATION_METHOD_NTLM and is_hash:
            self.logger.console_logger.debug(
                "A hash was given, but the authentication method " +
                f"{authentication_method} does not support pass the hash, skipping.")
            return False

        if authentication_method == AUTHENTICATION_METHOD_BEARER:
            # Authenticate
            # POST /oauth2/token
            authenticationPost = {"password": password, "grant_type": "password", "username": username}
            if domain:
                authenticationPost["username"] = f"{domain}\\{username}"
            response = session.post(f"{self.url}{AUTH_PATH}", data=authenticationPost)
            if "access_token" not in response.json():
                self.logger.console_logger.debug(
                    f"User {domain}\\{username} could not authenticate to {self.url}, retrying without domain")
                authenticationPost["username"] = username
                response = session.post(f"{self.url}{AUTH_PATH}", data=authenticationPost)
                if "access_token" not in response.json():
                    self.logger.console_logger.debug(f"User {username} could not authenticate")
                    return False

            bearer = response.json()["access_token"]
            session.headers["Authorization"] = f"bearer {bearer}"
            return True

        elif authentication_method == AUTHENTICATION_METHOD_NTLM:
            u = username
            if domain:
                u = f"{domain}\\{username}"
            ntlm_url = self.url + NTLM_PATH + '/sswinauthwebservice.asmx'
            hash = password
            if not is_hash:
                hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            session.auth = HttpNtlmAuth(u, "0" * 32 + ":" + hash)
            response = session.get(ntlm_url)
            if response.status_code != 200:
                return False
            return True
        return False

    def list_secrets(self, session: requests.Session, authentication_method: str) -> 'list[SecretListItem]':
        if authentication_method == AUTHENTICATION_METHOD_BEARER:
            # List secrets :
            # GET /api/v1/secrets?filter.searchText=&filter.isExactMatch=false&take=100
            return self._list_secrets(session, API_PATH)
        elif authentication_method == AUTHENTICATION_METHOD_NTLM:
            return self._list_secrets(session, NTLM_PATH + API_PATH)

    def _list_secrets(self, session: requests.Session, url_auth_method: str) -> 'list[SecretListItem]':
        skip = 0
        items_per_page = self.page_size
        secrets_ids = []
        secrets_endpoint_url = self.url + url_auth_method + SECRETS_PATH
        query = "?filter.searchText=&filter.isExactMatch=false&take="

        response = session.get(
            f"{secrets_endpoint_url}{query}{items_per_page}&skip={skip}")
        page_count = response.json()["pageCount"]

        self.logger.console_logger.info(f"Found {response.json()['total']} secrets for user, listing...")

        self._add_secrets(response.json()["records"], secrets_ids)

        if page_count > 1:
            for i in range(1, page_count):
                skip = i * items_per_page
                response = session.get(
                    f"{secrets_endpoint_url}{query}{items_per_page}&skip={skip}")
                self._add_secrets(response.json()["records"], secrets_ids)

        return secrets_ids

    def get_secrets_threaded(self, secret_items: 'list[SecretListItem]', found_secrets_list: NodesList,
                             session: requests.Session, secret_lines_output: 'list[str]',
                             authentication_method: str):
        if authentication_method == AUTHENTICATION_METHOD_BEARER:
            self._get_secrets_threaded(secret_items, found_secrets_list, session,
                                       secret_lines_output, API_PATH)
        elif authentication_method == AUTHENTICATION_METHOD_NTLM:
            self._get_secrets_threaded(secret_items, found_secrets_list, session,
                                       secret_lines_output, NTLM_PATH + API_PATH)

    def _get_secrets_threaded(self, secret_items: 'list[SecretListItem]', found_secrets_list: 'list[SSNode]',
                              session: requests.Session, secret_lines_output: 'list[str]',
                              url_auth_method: str):
        # Get secret details :
        # GET /api/v1/secrets/{secretId}
        for secret in secret_items:
            response = session.get(f"{self.url}{url_auth_method}{SECRETS_PATH}/{secret.unique_id}")
            if response.status_code == 401 or \
                    ('errorCode' in response.json() and response.json()["errorCode"] == "API_AccessDenied"):
                new_node = SSNode(secret.unique_id)
                new_node.got_denied = True
                found_secrets_list.append(new_node)
                continue

            new_node = SSNode(secret.unique_id)

            response_json = response.json()
            name = response_json["name"]

            for item in response_json["items"]:
                if item['isFile']:
                    out_file_name = f"{secret.unique_id}-{item['filename']}"
                    new_node.is_file = True
                    new_node.file_name = out_file_name
                    if not new_node.already_found:
                        # Get secret fields values :
                        # GET /api/v1/secrets/{secretId}/fields/{slug}
                        file_content_res = session.get(
                            f"{self.url}{url_auth_method}{SECRETS_PATH}/{secret.unique_id}/fields/{item['slug']}")
                        self.logger.log_secret_file(out_file_name, file_content_res.content)

                        secret_lines_output.append(
                            self.logger.get_secret_log_line(
                                [str(response_json['id']), response_json['name'],
                                 item['fieldName'], out_file_name, item['fieldDescription']]))

                else:
                    if Utils.is_username_like(item['fieldName']):
                        new_node.username = item['itemValue']
                    elif Utils.is_password_like(item['fieldName']):
                        new_node.password = item['itemValue']
                    elif item['fieldName'] == 'Domain':
                        new_node.domain = item['itemValue']

                    if not new_node.already_found:
                        secret_lines_output.append(
                            self.logger.get_secret_log_line(
                                [str(response_json['id']), response_json['name'],
                                 item['fieldName'], item['itemValue'], item['fieldDescription']]))
            if not new_node.domain and new_node.username:
                new_node.domain = self._extract_possible_domain_from_secret_name(name, new_node.username)

            found_secrets_list.append(new_node)

    def _add_secrets(self, secrets_records: list, secret_array: list):
        for record in secrets_records:
            secret_array.append(SecretListItem(record['id']))

    def _extract_possible_domain_from_secret_name(self, name, username):
        try:
            match = re.match(f"[ \\t]*([a-zA-Z0-9\\-\\.]+)\\\\{username}[ \\t]*", name, re.IGNORECASE)
            if match and match.group(1):
                domain = match.group(1)
                self.logger.console_logger.debug(
                    f"No domain was found so using found domain in the field name: {name} --> {domain}")
                return domain
        except:
            self.logger.console_logger.error('Error trying to extract a domain name from the field name, continuing...')
        return ''
