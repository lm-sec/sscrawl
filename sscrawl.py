#!/usr/bin/python3

# Secret Server Crawl
import os
import logging
import urllib3
import requests
import argparse
import numpy as np
from io import TextIOWrapper

from utils.sscrawl_logger import SSCrawlLogger
from utils.argparse_help_formatter import SortingHelpFormatter
from secret_servers.secret_server import SecretServer
from secret_servers.secret_server_node import SSNode
from secret_servers.get_secrets_thread import GetSecretsThread
from secret_servers.thycotic.thycotic_secret_server import ThycoticSecretServer
from secret_servers.hashicorp_vault.hashicorp_vault_secret_server import HashicorpVaultSecretServer
from secret_servers.authentication_method_not_supported_exception import AuthenticationMethodNotSupportedException

# Disable HTTPS invalid cert warning and key too small
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    # no pyopenssl support used / needed / available
    pass

DEFAULT_THREADS = 10
DEFAULT_SSCRAWL_OUT = "sscrawl_secrets.out"
DEFAULT_SSCRAWL_OUT_FOLDER = "sscrawl_files"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
DEFAULT_GRAPH_OUT = "graph.plantuml"
GRAPH_LEGEND = """\
Graph legend:
Red    : Access denied
Blue   : Already found
Green  : Is a file
Orange : No credentials found in secret, investigate
"""

DELINEA_SERVER = "delinea"
HASHICORP_SERVER = "hashicorp"
SUPPORTED_SERVERS = [DELINEA_SERVER, HASHICORP_SERVER]

LOGGING_FORMAT = '[%(asctime)s] %(levelname)-7s: %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def get_secrets(domain: str, username: str, password: str, proxies: 'dict[str, str]',
                is_hash: bool, is_secure: bool,  out_folder: str, out_file: str, node: SSNode,
                found_history: set, recursive: bool, thread_count: int, secret_server: SecretServer):
    logger.console_logger.info(f"------ {username}")
    secret_lines_output: 'list[list[str]]' = []
    found_children = []
    for auth_method in secret_server.authentication_methods:
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        session.proxies = proxies
        session.verify = is_secure
        auth_success = False
        try:
            logger.console_logger.info(
                f"Attempting to login with {username} with authentication method {auth_method}")
            auth_success = secret_server.connect_session(domain, username, password,
                                                         session, auth_method, is_hash)
        except AuthenticationMethodNotSupportedException as err:
            logger.console_logger.error(err)
            exit()
        except Exception as err:
            print(err)
            logger.console_logger.error(f'Unknown error while trying to authenticate with {username}')
            logger.console_logger.error(err)
            auth_success = False

        if not auth_success:
            logger.console_logger.info(f"Login failure with user {username} with authentication method {auth_method}")
            continue

        logger.console_logger.info(f"Login success with user {username} with authentication method {auth_method}")
        secret_ids = secret_server.list_secrets(session, auth_method)

        logger.console_logger.info(f"Listed {len(secret_ids)} secrets, attempting to read...")

        # CALL WITH THREADS
        secrets_list = np.array_split(secret_ids, thread_count)
        get_secrets_threads: 'list[GetSecretsThread]' = []
        for i in range(thread_count):
            if len(secrets_list[i]) > 0:
                found_children.append(list())
                secret_lines_output.append(list())
                get_secrets_threads.append(
                    GetSecretsThread(secrets_list[i], found_children[len(found_children) - 1],
                                     session, secret_lines_output[len(secret_lines_output) - 1],
                                     secret_server, found_history, auth_method))
                get_secrets_threads[len(get_secrets_threads) - 1].start()

        for t in get_secrets_threads:
            t.join()

    # Join output, write to files
    for line in secret_lines_output:
        text = "".join(line)
        logger.log_secret_to_file(text)

    for children_list in found_children:
        node.children.extend(children_list)

    if logger.verbose:
        for child in node.children:
            child_data_separator = " :"
            child_data = child_data_separator
            if child.already_found:
                child_data += " (Already found)"
            if child.username:
                child_data += f" Username: {child.username}"
            if child.password:
                child_data += f" Password: {child.password}"
            if child.file_name:
                child_data += f" File Name: {child.file_name}"

            logger.console_logger.debug(
                f"Found secret ID {child.readable_id}" +
                f"{child_data if len(child_data) > len(child_data_separator) else ''}")

    read_secret_count = 0
    for child in node.children:
        if not child.got_denied:
            read_secret_count += 1

    logger.console_logger.info(f"Logged a total of {read_secret_count} secrets accross all authentication methods")

    if recursive:
        for child in node.children:
            if not child.username or not child.password or child.already_found:
                continue
            d = GLOBAL_DOMAIN
            if child.domain:
                d = child.domain
            get_secrets(d, child.username, child.password, proxies,
                        False, is_secure, out_folder, out_file, child,
                        found_history, recursive, thread_count, secret_server)


def node_name(node: SSNode, parentId: str):
    return f"{parentId}{node.id}"


def node_text(node: SSNode):
    text = f"\"ID: {node.readable_id}"
    if node.domain:
        text += f"\\nDomain: {node.domain}"
    if node.username:
        text += f"\\nUser: {node.username}"
    if node.file_name:
        text += f"\\nFile: {os.path.basename(node.file_name)}"
    return text + '"'


def node_to_str(node: SSNode, parentId: str):
    color = ""

    if not node.username and not node.file_name:
        color = "#ff9430"  # orange

    if node.is_file:
        color = "#31d65d"  # green

    if node.already_found:
        color = "#5a89ed"  # blue

    if node.got_denied:
        color = "#f74343"  # red

    return f"rectangle {node_text(node)} as {node_name(node, parentId)} {color}\n"


def node_arrow(node1: SSNode, parentId: str, node2: SSNode):
    return f"{node_name(node1, parentId)} --> {node_name(node2, node1.id)}\n"


def recursive_generate_graph(node: SSNode, file: TextIOWrapper,
                             parentId: str, arrow_strings: set,
                             print_already_found: bool, print_access_denied: bool):
    if (not node.already_found and not node.got_denied) or \
            (print_already_found and node.already_found) or \
            (print_access_denied and node.got_denied):
        file.write(node_to_str(node, parentId))
    for n in node.children:
        if (not node.already_found and not n.already_found and not node.got_denied and not n.got_denied) or \
                (print_already_found and n.already_found) or \
                (print_access_denied and n.got_denied):
            arrow_strings.add(node_arrow(node, parentId, n))
        recursive_generate_graph(n, file, node.id, arrow_strings, print_already_found, print_access_denied)


def generate_graph(root_node: SSNode, graph_out_file: str, print_already_found: bool, print_access_denied: bool):
    arrow_strings = set()
    with open(graph_out_file, 'w') as f:
        f.write("@startuml\nleft to right direction\n")
        f.write("skinparam rectangle {\nBorderColor Transparent\n}\n")
        recursive_generate_graph(root_node, f, '', arrow_strings, print_already_found, print_access_denied)
        for arrow in arrow_strings:
            f.write(arrow)
        f.write("@enduml\n")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSCrawl crawls secret servers for secrets and files.",
        formatter_class=SortingHelpFormatter)

    parser.add_argument("-d", "--domain",
                        help="The active directory domain name to be prepended to the \
                            username during connection as domain\\username",
                        default="", required=False)
    parser.add_argument("-s", "--server",
                        help=f"The secret server type/vendor [{', '.join(SUPPORTED_SERVERS)}]",
                        required=True, type=str, choices=SUPPORTED_SERVERS)
    parser.add_argument("-u", "--user",
                        help="The username to authenticate to the secret server. Can be a role_id.",
                        required=True, type=str)
    parser.add_argument("-p", "--pwd",
                        help="The password to authenticate to the secret server Can be a secret_id.",
                        required=False, type=str)
    parser.add_argument("-l", "--url",
                        help="The URL of the secret server API",
                        required=True, type=str)
    parser.add_argument("-o", "--out",
                        help=f"The output secret file name, default {DEFAULT_SSCRAWL_OUT}",
                        required=False, type=str, default=DEFAULT_SSCRAWL_OUT)
    parser.add_argument("-O", "--outfolder",
                        help=f"The output folder where to write files, default {DEFAULT_SSCRAWL_OUT_FOLDER}",
                        required=False, type=str, default=DEFAULT_SSCRAWL_OUT_FOLDER)
    parser.add_argument("-c", "--pagesize",
                        help="The number of secrets per page, default 100, when relevant",
                        required=False, type=int, default=100)
    parser.add_argument("-v", "--verbose",
                        help="Increases output verbosity",
                        action="store_true")
    parser.add_argument("-P", "--proxy",
                        help="Passes the connections through the provided proxy",
                        required=False)
    parser.add_argument("-r", "--recursive",
                        help="The script will recursively try found username/password combinations \
                        to find more secrets",
                        default=False, action="store_true")
    parser.add_argument("-g", "--graph",
                        help="Graph the found credentials to represent the links between them",
                        default=False, action="store_true")
    parser.add_argument("-G", "--graphfile",
                        help=f"The graph file name, default {DEFAULT_GRAPH_OUT}",
                        required=False, type=str, default=DEFAULT_GRAPH_OUT)
    parser.add_argument("-t", "--threads",
                        help=f"The amount of threads with which to query the server, defaults to {DEFAULT_THREADS}",
                        required=False, type=int, default=DEFAULT_THREADS)
    parser.add_argument("-H", "--hash",
                        help="The ntlm hash to perform a pass the hash attack on the authentication, when supported",
                        required=False, type=str)
    parser.add_argument("-k", "--insecure",
                        help="Skip tls host validation when negotiating tls",
                        required=False, action="store_false")
    parser.add_argument("-n", "--noalreadyfound",
                        help="Do not show in the graph the secrets that were already found",
                        required=False, action="store_false")
    parser.add_argument("-N", "--noaccessdenied",
                        help="Do not show in the graph the secrets for which the access was denied",
                        required=False, action="store_false")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    out_file = args.out
    graph_file = args.graphfile

    logger = SSCrawlLogger(
        logging.getLogger('SSCrawl'),
        args.verbose, out_file, args.outfolder)

    if args.out == DEFAULT_SSCRAWL_OUT:
        out_file = os.path.join(args.outfolder, args.out)

    if args.graphfile == DEFAULT_GRAPH_OUT:
        graph_file = os.path.join(args.outfolder, args.graphfile)

    proxies = {}
    if args.proxy is not None:
        parsed = urllib3.util.parse_url(args.proxy)
        if all([parsed.scheme, parsed.host]):
            proxies = {'http': args.proxy, 'https': args.proxy}
        else:
            logger.console_logger.error("Invalid proxy url provided, please validate.")
            exit(1)

    if not args.pwd and not args.hash:
        logger.console_logger.error("At least --pwd or --hash must be provided")
        exit()

    pwd = args.pwd
    is_hash = False
    if args.hash:
        is_hash = True
        pwd = args.hash

    root_node = SSNode('__root_node__', True)
    root_node.username = args.user
    root_node.password = args.pwd
    found_history = set()

    if args.server == DELINEA_SERVER:
        ss = ThycoticSecretServer(logger, args.url, args.pagesize)
    elif args.server == HASHICORP_SERVER:
        ss = HashicorpVaultSecretServer(logger, args.url)
    else:
        exit()

    GLOBAL_DOMAIN = args.domain

    for arg in args._get_kwargs():
        logger.console_logger.debug(f"{arg[0].ljust(16, ' ')}: {arg[1]}")

    get_secrets(args.domain, args.user, pwd, proxies,
                is_hash, args.insecure, args.outfolder, out_file, root_node,
                found_history, args.recursive, args.threads, ss)

    if args.graph:
        print("")
        generate_graph(root_node, graph_file, args.noalreadyfound, args.noaccessdenied)
