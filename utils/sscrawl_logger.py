import logging
import os

LOGGING_FORMAT = '[%(asctime)s] %(levelname)-7s: %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

class SSCrawlLogger():
    def __init__(self, logger: logging.Logger, verbose: bool, secrets_file_name: str, secrets_folder_name: str, separator = "|||"):
        self.console_logger: logging.Logger = logger
        formatter = logging.Formatter(LOGGING_FORMAT, DATE_FORMAT)
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.console_logger.addHandler(handler)
        self.verbose = verbose
        if verbose:
            self.console_logger.setLevel(logging.DEBUG)
        else:
            self.console_logger.setLevel(logging.INFO)

        self.secrets_file_name = secrets_file_name
        self.secrets_folder_name = secrets_folder_name
        self.separator = separator
    
        # Create secrets folder if not exist
        os.makedirs(secrets_folder_name, exist_ok=True)

    def log_secret_to_file(self, line: str):
        """Logs a secret to the secret file"""
        with open(self.secrets_file_name, 'a') as f:
            f.write(line)

    def log_secret_file(self, secret_file_name: str, content: bytes):
        """Logs the binary content of a file from the secret server to a file on disk"""
        file = secret_file_name
        if self.secrets_folder_name:
            file = self.secrets_folder_name + '/' + secret_file_name
        with open(file, "wb") as f:
            f.write(content)


    def get_secret_log_line(self, items: list):
        """Return the text that should be logged to the secrets file"""
        line = ''
        for item in items:
            line += f"{item}{self.separator}"
        return f"{line[:-len(self.separator)]}\n"
