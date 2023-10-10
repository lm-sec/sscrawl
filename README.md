# SSCrawl

A multi-threaded Secret Server Crawler. It uses the initial credentials to connect to the secret server and reads all credentials and files. It then tries to re-login recursively with the found credentials. Secrets tree graphs are generated for better access visualisation.

## Supported Servers

* Delinea Secret Server (formerly Thycotic)
* HashiCorp Vault

## Help

```text
usage: sscrawl.py [-h] [-d DOMAIN] -s {delinea,hashicorp} -u USER [-p PWD] -l URL [-o OUT] [-O OUTFOLDER] [-c PAGESIZE] [-v] [-P] [-r] [-g] [-G GRAPHFILE] [-t THREADS] [-H HASH] [-n] [-N]

SSCrawl crawls secret servers for secrets and files.

optional arguments:
  -G GRAPHFILE, --graphfile GRAPHFILE
                        The graph file name, default graph.plantuml
  -H HASH, --hash HASH  The ntlm hash to perform a pass the hash attack on the authentication, when supported
  -N, --noaccessdenied  Do not show in the graph the secrets for which the access was denied
  -O OUTFOLDER, --outfolder OUTFOLDER
                        The output folder where to write files, default sscrawl_files
  -P, --proxy           Passes the connections through http://localhost:8080
  -c PAGESIZE, --pagesize PAGESIZE
                        The number of secrets per page, default 100, when relevant
  -d DOMAIN, --domain DOMAIN
                        The active directory domain name to be prepended to the username during connection as domain\username
  -g, --graph           Graph the found credentials to represent the links between them
  -h, --help            show this help message and exit
  -l URL, --url URL     The URL of the secret server API
  -n, --noalreadyfound  Do not show in the graph the secrets that were already found
  -o OUT, --out OUT     The output secret file name, default sscrawl_secrets.out
  -p PWD, --pwd PWD     The password to authenticate to the secret server Can be a secret_id.
  -r, --recursive       The script will recursively try found username/password combinations to find more secrets
  -s {delinea,hashicorp}, --server {delinea,hashicorp}
                        The secret server type/vendor [delinea, hashicorp]
  -t THREADS, --threads THREADS
                        The amount of threads with which to query the server, defaults to 10
  -u USER, --user USER  The username to authenticate to the secret server. Can be a role_id.
  -v, --verbose         Increases output verbosity
```

### Examples

Non-recursive search with a HashiCorp username and password login, without graph generation :

```bash
python3 sscrawl.py --user 'User01' -p 'password01' --server 'hashicorp' --url "http://192.168.59.104:8200"
```

Recursive search with a HashiCorp approle login, with graph generation :

```bash
python3 sscrawl.py --user 'aafab6b2-4de6-b72f-d8b2-e7c95d1d162a' -p '75091e8c-0c11-510e-b1e3-e87ddd50c27c' --server 'hashicorp' --url "http://192.168.59.104:8200" --graph --recursive
```
