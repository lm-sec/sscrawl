import threading
import requests

from secret_servers.secret_server import SecretServer
from secret_servers.secret_server_node import SSNode


class GetSecretsThread(threading.Thread):
    def __init__(self, secrets_ids: 'list[str]', found_childs_list: 'list[SSNode]',
                 session: requests.Session, secret_lines_output: 'list[str]',
                 secret_server: SecretServer, found_ids_history: set, auth_method: str):
        self.secrets_ids = secrets_ids
        self.found_childs_list = found_childs_list
        self.session = session
        self.secret_lines_output = secret_lines_output
        self.secret_server = secret_server
        self.found_ids_history = found_ids_history
        self.auth_method = auth_method
        super().__init__()

    def run(self):
        self.secret_server.get_secrets_threaded(
            self.secrets_ids, self.found_childs_list, self.session,
            self.found_ids_history, self.secret_lines_output, self.auth_method)
