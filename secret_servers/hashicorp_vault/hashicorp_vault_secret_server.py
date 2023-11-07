import requests

from utils.utils import Utils
from utils.sscrawl_logger import SSCrawlLogger

from secret_servers.secret_server_node import SSNode
from secret_servers.secret_server import SecretServer
from secret_servers.hashicorp_vault.hashicorp_secret_list_item import HashicorpSecretListItem
from secret_servers.authentication_method_not_supported_exception import AuthenticationMethodNotSupportedException
from secret_servers.hashicorp_vault.hashicorp_vault_constants import (API_V1, AUTHENTICATION_APPROLE_PATH,
                                                                      AUTHENTICATION_METHOD_APPROLE,
                                                                      AUTHENTICATION_METHOD_USER_PASS,
                                                                      AUTHENTICATION_USERPASS_PATH,
                                                                      IDENTITY_ROUTE, LISTING_SECRETS_ENGINES_PATH,
                                                                      SECRET_ENGINE_CUBBYHOLE, SECRET_ENGINE_KV,
                                                                      SECRET_ENGINE_KVV1, SECRET_ENGINE_KVV2,
                                                                      SECRETS_ENGINES_FIELD, SYS_ROUTE,
                                                                      VAULT_TOKEN_HEADER)


class HashicorpVaultSecretServer(SecretServer):
    def __init__(self, logger: SSCrawlLogger, url: str, ):
        super().__init__(logger, url)
        self.authentication_methods = [AUTHENTICATION_METHOD_USER_PASS, AUTHENTICATION_METHOD_APPROLE]

    def connect_session(self, domain: str, username: str, password: str,
                        session: requests.Session, authentication_method: str, is_hash: bool) -> bool:
        """Connect to hashicorp vault using the authentication method

        is_hash is not supported
        """

        if is_hash:
            raise AuthenticationMethodNotSupportedException(
                "Hashicorp vault login does not support pass-the-hash. A hash cannot be supplied to login.")

        if authentication_method == AUTHENTICATION_METHOD_USER_PASS:
            # POST /v1/auth/userpass/login/<UsernameHere>
            auth_data = {
                "password": password
            }
            session.headers["Content-Type"] = "application/json"
            response = {}
            try:
                response = session.post(f"{self.url}{AUTHENTICATION_USERPASS_PATH}/{username}", json=auth_data)
                return self._extract_client_token(session, response, authentication_method)
            except:
                self.logger.console_logger.debug(
                    f"Error while authenticating with authentication method {authentication_method}")
                if response.content:
                    self.logger.console_logger.debug(str(response.content))
                return False

        elif authentication_method == AUTHENTICATION_METHOD_APPROLE:
            # curl --request POST --data @appserver01_login.json $VAULT_ADDR/v1/auth/approle/login | jq
            if not Utils.is_valid_uuid(username):
                self.logger.console_logger.debug(
                    "The client_id is not in the form of a UUID.\
                     It is unexpected for the approle login method. Skipping.")
                return False

            auth_data = {
                "role_id": username,
                "secret_id": password
            }

            session.headers["Content-Type"] = "application/json"
            response = {}
            try:
                response = session.post(f"{self.url}{AUTHENTICATION_APPROLE_PATH}", json=auth_data)
                return self._extract_client_token(session, response, authentication_method)
            except:
                self.logger.console_logger.debug(
                    f"Error while authenticating with authentication method {authentication_method}")
                if response.content:
                    self.logger.console_logger.debug(str(response.content))
                return False

        return False  # Authentication method not implemented

    def list_secrets(self, session: requests.Session, authentication_method: str) -> 'list[HashicorpSecretListItem]':
        """List the secrets that the user can list. Some may be non-readable by the user"""
        # curl -v --header "X-Vault-Token: $APP_TOKEN" --request GET $VAULT_ADDR/v1/sys/internal/ui/mounts | jq -r
        response = {}
        engines_dict: dict = {}
        engine_routes = []
        final_secrets_list: 'list[HashicorpSecretListItem]' = []

        # Listing secrets engines
        try:
            session.headers["Content-Type"] = "application/json"
            response = session.get(f"{self.url}{LISTING_SECRETS_ENGINES_PATH}")
            content_json = response.json()
            if SECRETS_ENGINES_FIELD not in content_json["data"]:
                self.logger.console_logger.debug("No secret engines found, empty list will be returned")
                return []
            engines_dict = content_json["data"][SECRETS_ENGINES_FIELD]
            # The keys represent a secrets engine route, like "cubbyhole/", "secrets/", etc.
            engines_keys: set = engines_dict.keys()
            for key in engines_keys:
                if key == IDENTITY_ROUTE or key == SYS_ROUTE:
                    continue
                engine_routes.append(key)
        except Exception as e:
            self.logger.console_logger.debug("Error while listing secrets engines, empty list will be returned")
            if response.content:
                self.logger.console_logger.debug(str(response.content))
            return []

        # Listing secrets for every secrets engines
        for key in engine_routes:
            # Only supported engine types are kv v1, kv v2 and cubbyhole
            engine_type = ""
            if engines_dict[key]["type"] == SECRET_ENGINE_KV:
                if "options" in engines_dict[key] and \
                        "version" in engines_dict[key]["options"] and \
                        engines_dict[key]["options"]["version"] == "2":
                    engine_type = SECRET_ENGINE_KVV2
                else:
                    engine_type = SECRET_ENGINE_KVV1
            elif engines_dict[key]["type"] == SECRET_ENGINE_CUBBYHOLE:
                engine_type = SECRET_ENGINE_CUBBYHOLE
            else:
                continue
            self._list_secrets_recursive(session, key, engine_type, "", final_secrets_list)

        return final_secrets_list

    def _list_secrets_recursive(self, session: requests.Session, engine_path: str,
                                engine_type: str, current_local_path: str,
                                secrets_list: 'list[HashicorpSecretListItem]'):
        res = {}
        if engine_type == SECRET_ENGINE_CUBBYHOLE or engine_type == SECRET_ENGINE_KVV1:
            # LIST $VAULT_ADDR/v1/{engine_path}/ ( kvv1, cuubyhole )
            res = session.request("LIST", f"{self.url}{API_V1}/{engine_path}{current_local_path}")
        elif engine_type == SECRET_ENGINE_KVV2:
            # LIST $VAULT_ADDR/v1/{engine_path}/metadata/ ( kvv2 )
            res = session.request("LIST", f"{self.url}{API_V1}/{engine_path}metadata/{current_local_path}")
        if res.status_code == 200:
            new_secrets_list = res.json()["data"]["keys"]

            for secret in new_secrets_list:
                if secret[-1] == "/":
                    self._list_secrets_recursive(session, engine_path, engine_type,
                                                 current_local_path + secret, secrets_list)
                else:
                    secrets_list.append(HashicorpSecretListItem(engine_type, engine_path, current_local_path + secret))

    def get_secrets_threaded(self, secret_items: 'list[HashicorpSecretListItem]', found_secrets_list: 'list[SSNode]',
                             session: requests.Session, found_ids_history: set, secret_lines_output: 'list[str]',
                             authentication_method: str):
        """Get a key/value or cubbyhole secret from the vault"""
        for secret in secret_items:
            # As hashicorp vault is fully path based, the id represents the full path to the secret
            response = session.get(f"{self.url}{API_V1}{secret.unique_id}")
            if response.status_code == 403 or response.status_code == 401:
                self.logger.console_logger.debug(f"Access denied for secret id {secret.unique_id}")
                new_node = SSNode(secret.unique_id)
                new_node.got_denied = True
                found_secrets_list.append(new_node)
                continue

            new_node = SSNode(secret.unique_id)
            if secret.unique_id in found_ids_history:
                new_node.already_found = True

            found_ids_history.add(secret.unique_id)
            response_json = response.json()

            data_dict = \
                response_json["data"] if \
                (secret.secret_engine_type == SECRET_ENGINE_CUBBYHOLE or
                 secret.secret_engine_type == SECRET_ENGINE_KVV1) \
                else response_json["data"]["data"]
            keys = data_dict.keys()

            for key in keys:
                if Utils.is_username_like(key):
                    new_node.username = data_dict[key]
                elif Utils.is_password_like(key):
                    new_node.password = data_dict[key]

                try:
                    if Utils.is_file_like(data_dict[key]):
                        content: str = data_dict[key]
                        new_node.is_file = True
                        file_name = f"{secret.unique_id.replace('/', '_')}-{key}"
                        new_node.file_name = file_name
                        self.logger.log_secret_file(file_name, content.encode())

                        secret_lines_output.append(
                            self.logger.get_secret_log_line(
                                [secret.unique_id, secret.secret_local_path, key, file_name]))
                    else:
                        secret_lines_output.append(
                            self.logger.get_secret_log_line(
                                [secret.unique_id, secret.secret_local_path, key, data_dict[key]]))
                except:
                    self.logger.console_logger.debug(
                        f"Error while handling the secret at {secret.unique_id}, will attempt to continue")

            found_secrets_list.append(new_node)

    def _extract_client_token(self, session: requests.Session, response: requests.Response, auth_method: str) -> bool:
        if response.status_code != 200:
            self.logger.console_logger.debug(f"Status code {str(response.status_code)} on {auth_method} login")
            return False

        content_json = response.json()
        if not content_json["auth"] or not content_json["auth"]["client_token"]:
            self.logger.console_logger.debug(
                f"No auth.client_token in response content, {auth_method} authentication failed")
            return False

        token = content_json["auth"]["client_token"]
        session.headers[VAULT_TOKEN_HEADER] = token
        return True
