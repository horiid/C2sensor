
import re, requests, subprocess, os, chardet, pprint, concurrent.futures
from json import JSONDecodeError, JSONDecoder
from random import randint
from requests.adapters import HTTPAdapter, PoolManager
from monitor_agent.csvutils import CsvParseIndex as csvidx
from models.schema import MonitoringStat

# Adapter class for setting destination port
class SourcePortAdapter(HTTPAdapter):
    def __init__(self, port, *args, **kwargs):
        self._source_port = port
        super(SourcePortAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize,
                                       block=block, source_address=('', self._source_port))


# Concurrent processing for network I/O

def print_threat_id(_id):
    print('''
\n==========================
Threat ID: {0}
==========================
'''.format(_id))

def monitoring_stat(row: list, observe_time:str):
    HTTP_ = 80
    HTTPS_ = 443
    print_threat_id(row[csvidx.UID])
       # prepare HTTP header for send_http()
    req_header = {"Accept-Encoding": "gzip,deflate", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36",
                  "Host": ""}
       # get data from row for Monitoring class initialization
    if row[csvidx.DOMAIN]:
        # domain name e.g. example.com
        input = row[csvidx.DOMAIN]
        req_header['Host'] = input
    elif row[csvidx.URL]:
        # ignore schema e.g. http://, https://, ftp://.
        input = row[csvidx.URL].split('//', 1)[1]
        # ignore directory part
        req_header['Host'] = input.split('/', 1)[0]
    elif row[csvidx.HOST]:
        # IPv4
        input = row[csvidx.HOST]
        req_header['Host'] = input
    else:
        # There's no information of domain name or IP, so skip this row.
        print('IP address or domain name is not provided. Skipped this row.\n')
        return
    input = input.replace('[', '').replace(']', '')

    domain_name = [row[csvidx.DOMAIN].replace('[', '').replace(']', '')]
    ipv4_addr = [row[csvidx.HOST].replace('[', '').replace(']', '')]

    # Get hashes
    hashes = row[csvidx.HASH]
    try:
        # if #hash is not subscriptable, raise KeyError and exit.
        if hashes != "" and "{" not in hashes:
            raise KeyError
        json_decoder = JSONDecoder()
        hashes, i = json_decoder.raw_decode(hashes)
        if i in locals():
            del i
    except JSONDecodeError:
        print('No hash info found. Proceeding.\n')
    except KeyError:
        print("#hash info found, but failed to identify the algorithm.")
        hashes = ['']
        # parse row[file type] and if there are multiple file info, store data to 'files'
        # otherwise store a file information to 'file'.
        # Store file info to variables
    file_cnt = 0
    file_list = row[csvidx.FILE_TYPE].split(',')
    mal_file = {"file-type": "", "name": "", "hashes": {"md5": "", "sha1": "", "sha256": ""}}
    mal_files = []
    for file in file_list:
        if file != '':
            print('\n==FOUND FILE INFO==\nFILE TYPE:', file)
            pprint.pprint(hashes[file_cnt])
            print("\n")
            mal_file["file-type"] = file
            mal_file["hashes"] = hashes[file_cnt]
            mal_files.append(mal_file.copy())
            file_cnt += 1
    if file_cnt == 1:
        mal_files = []
    # Preprocessing for  sending data to C2 servers
    src_port = randint(49152, 65535)
    dst_port = None
    # PORT is empty
    if row[csvidx.PORT] == '':
        dst_port = HTTP_
    # PORT has multiple port number
    elif "," in row[csvidx.PORT]:
        dst_port = row[csvidx.PORT].split(',')[1]
        if "443" in dst_port:
            dst_port = HTTPS_
        else:
            dst_port = HTTP_
    # single PORT number
    else:
        dst_port = row[csvidx.PORT]
        try:
            dst_port = int(dst_port)
        except:
            print(row[csvidx.PORT], "is not expected as a port number.")
            dst_port = HTTP_
    # Send ping & HTTP "GET" request
    network_traffic = {'src-port': src_port, 'dst-port': dst_port}
    ping, http_ext = monitor(
        host=input, src_port=src_port, dst_port=dst_port, http_headers=req_header)
    print(ping, http_ext)
    http_version = ''
    http_response_ext = {'status_code': '', 'reason_phrase': ''}
    # Received HTTP response
    if http_ext is not None:
        http_response_ext['status_code'] = http_ext[0]
        http_response_ext['reason_phrase'] = http_ext[1]
        if http_ext[2] == 10:
            http_version = "http/1.0"
        elif http_ext[2] == 11:
            http_version = "http/1.1"
        # else, it is unknown.

    try:
        req_value = row[csvidx.URL].split('//', 1)[1].split('/', 1)[1]
    except IndexError:
        print('URL is not provided in CSV file.')
        req_value = ''
    http_request_ext = {'request-method': 'get', 'request-value': req_value,
                        'request-version': http_version, 'request-header': req_header}
    # Append data to MonitoringStat instance
    monitor_ = MonitoringStat()
    monitor_.input = input
    monitor_.domain_name = domain_name
    monitor_.ipv4_addr = ipv4_addr
    monitor_.observe_time = observe_time
    monitor_.network_traffic = network_traffic
    monitor_.ping_ext = ping
    monitor_.http_request_ext = http_request_ext
    monitor_.http_response_ext = http_response_ext
    monitor_.file = mal_file
    monitor_.files = mal_files
    pprint.pprint(monitor_.monitoring)
    print('\n')

# Manages of send_ping and send_http
def monitor(host: str, src_port: int=None, dst_port:int=80, http_headers:dict=None):
    """Send ping and HTTP GET request

    monitor() sends ping and HTTP GET request with args given: 
    host, source port, and destination port.

    Args:
        host (str): Target host. It could be IP address, FQDN, or URL.
        src_port (int): Source port, which means a port for our side. None if not provided.
        dst_port (int): Destination port, which means a port for the target host. 80 if not provided.

    Returns:
        tuple: results of send_ping() and send_http(). Index: 0 for ping, 1 for HTTP.
        s_ping: See send_ping.
        s_http: 
            tuple: status_code (int), HTTP reason phrase (str), HTTP version (int)
            None: On failure/timeout.
    """
    print("Target host:", host)
    s_ping = send_ping(host)
    s_http = send_http(host=host, src_port=src_port,
                       dst_port=dst_port, headers=http_headers)
    if s_http is None:
        print("\nERROR in send_http")
    else:
        print("\nsend http:", s_http.status_code, s_http.reason)
        s_http = (s_http.status_code, s_http.reason, s_http.raw.version)
    return s_ping, s_http


# send ping
def send_ping(host, times="4"):
    """Send ping to specified host

    send_ping() sends ping to the host specified by the "host" argument.

    Args:
        host (str): Target host. It could be IP address, FQDN, or URL.
        times (int): number of times to send ping. 4 by default.

    Returns:
        dict: result of ping statistics. Keys are as follows:
              "loss": loss rate with % (str)
              "ttl": time-to-live (int)
              "rtt": average round trip time in miliseconds(ms) (str).
    """
    # option and pattern for UNIX-like platforms
    opt = '-c'
    # patterns to fetch loss rate, ttl, and rtt
    loss_pattern = r'([0-9]+\%) packet loss'
    ttl_pattern = r'ttl=([0-9]+)'
    rtt_pattern = r'rtt.*= .*/(.*)/.*/.* ms'
    # Change option and pattern if the platform is windows NT
    if os.name == 'nt':
        opt = '-n'
        loss_pattern = r'([0-9]+\%) の損失'
        rtt_pattern = r'平均 = ([0-9]+)ms'
    print("Sending ping to...", host)
    ping = subprocess.run(["ping", opt, times, host], stdout=subprocess.PIPE)
    try:
        # raise CalledProcessError if returncode is not zero
        ping.check_returncode()

        # fetch ping loss rate
        stdout = ping.stdout.decode(chardet.detect(ping.stdout)["encoding"])
        # Check Packet loss rate
        try:
            loss = re.search(loss_pattern, stdout).group(1)
        except AttributeError:
            loss = ""
        # Check Time-to-live
        try:
            ttl = re.search(ttl_pattern, stdout, re.IGNORECASE).group(1)
        except AttributeError:
            ttl = 0
        # Check Round time trip
        try:
            rtt = re.search(rtt_pattern, stdout).group(1) + "ms"
        except AttributeError:
            rtt = ""
        return {"loss": loss, "ttl": int(ttl), "rtt": rtt}
    except subprocess.CalledProcessError:
        return {"loss": "", "ttl": 0, "rtt": ""}


# send HTTP GET request and returns response
def  send_http(host: str, src_port: int=None, dst_port:int=80, headers:dict=None):
    """Send HTTP GET request to specified host

    send_http() sends HTTP GET request to the host provided by "host" argument.

    Args:
        host (str): Target host. It could be IP address, FQDN, or URL.
        src_port (int): Source port, which means a port for our side. None if not provided.
        dst_port (int): Destination port, which means a port for the target host. 80 if not provided.
        header (dict): headers for request. None if not provided.

    Returns:
        requsts.Response: results requests.Session.get(), which is obj: Response. 
        None: returns None when the function raised requests.ConnectionError or requests.Timeout.
    """
    if dst_port == 80:
        query = "http://"
    elif dst_port == 443:
        query = "https://"
    else:
        query = "http://"
        dst_port = 80

    if src_port is None or src_port <= 49151:
        src_port = randint(49152, 65535)
        print('Created random port  number:', src_port)
    sess = requests.Session()
    sess.mount(query, SourcePortAdapter(src_port))
    query = query + host + ":" + str(dst_port)
    try:
        print("\nSending HTTP request to", query + "...")
        response = sess.get(query, headers=headers, timeout=(4.0, 8.0), allow_redirects=False)
    except requests.ConnectionError:
        print('ERROR: Connection Error')
        return None
    except requests.Timeout:
        print('ERROR: Timeout')
        return None
    return response
