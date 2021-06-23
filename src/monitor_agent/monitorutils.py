
import re, requests, subprocess, os, re, chardet
from random import randint
from requests.adapters import HTTPAdapter, PoolManager


# Adapter class for setting destination port
class SourcePortAdapter(HTTPAdapter):
    def __init__(self, port, *args, **kwargs):
        self._source_port = port
        super(SourcePortAdapter, self).__init__(*args, **kwargs)
    
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, 
        block=block, source_address=('', self._source_port))


# Manages of send_ping and send_http
def monitor(host: str, src_port:int=None, dst_port:int=80, http_headers:dict=None):
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
    s_http = send_http(host=host, src_port=src_port, dst_port=dst_port, headers=http_headers)
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
    except  subprocess.CalledProcessError:
        return {"loss": "", "ttl": 0, "rtt": ""}


# send HTTP GET request and returns response
def  send_http(host: str, src_port:int=None, dst_port:int=80, headers:dict=None):
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
        response = sess.get(query, headers=headers, timeout=(4.0,8.0), allow_redirects=False)
    except requests.ConnectionError:
        print('ERROR: Connection Error')
        return None
    except requests.Timeout:
        print('ERROR: Timeout')
        return None
    return response
