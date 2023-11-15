from secret_servers.secret_server_node import SSNode
from utils.sscrawl_logger import SSCrawlLogger


class NodesList(list):
    """
    A SSNode list. When appending a secret, it will mark the item as already_found if it was.
    It will also log enverything that is appended to the list.
    """

    found_ids_history: set
    logger: SSCrawlLogger

    def __init__(self, found_ids_history: set, logger: SSCrawlLogger):
        self.found_ids_history = found_ids_history
        self.logger = logger
        super().__init__()

    def append(self, secret: SSNode):
        """Append a SSNode to the list. Also logs to the command line that a new secret was found."""
        if secret.id in self.found_ids_history:
            secret.already_found = True
        else:
            self.found_ids_history.add(secret.id)

        if self.logger.verbose:
            if not secret.got_denied:
                secret_data_separator = " :"
                secret_data = secret_data_separator
                if secret.already_found:
                    secret_data += " (Already found)"
                if secret.username:
                    secret_data += f" Username: {secret.username}"
                if secret.password:
                    secret_data += f" Password: {secret.password}"
                if secret.file_name:
                    secret_data += f" File Name: {secret.file_name}"

                self.logger.console_logger.debug(
                    f"Found secret ID {secret.readable_id}" +
                    f"{secret_data if len(secret_data) > len(secret_data_separator) else ''}")
            else:
                self.logger.console_logger.debug(f"Access denied for secret id {secret.readable_id}")
        
        super().append(secret)

        
