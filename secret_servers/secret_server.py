import requests
from abc import ABCMeta, abstractmethod

from utils.sscrawl_logger import SSCrawlLogger
from secret_servers.secret_server_node import SSNode
from secret_servers.secret_list_item import SecretListItem


class SecretServer(object, metaclass=ABCMeta):
    authentication_methods: 'list[str]'

    @abstractmethod
    def __init__(self, logger: SSCrawlLogger, url: str):
        self.logger = logger
        self.url = url

    @abstractmethod
    def connect_session(self, domain: str, username: str, password: str,
                        session: requests.Session, authentication_method: str,
                        is_hash: bool) -> bool:
        pass

    @abstractmethod
    def list_secrets(self, session: requests.Session, authentication_method: str) -> 'list[SecretListItem]':
        pass

    @abstractmethod
    def get_secrets_threaded(self, secret_items: 'list[SecretListItem]', found_secrets_list: 'list[SSNode]',
                             session: requests.Session, found_ids_history: set, secret_lines_output: 'list[str]',
                             authentication_method: str):
        pass
