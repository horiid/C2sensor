
import re, requests, subprocess, csv, os, re, chardet
from random import randint
from enum import IntEnum, auto
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


# Constants for reading elements of csv file
# Numbers are index of each row
# 1,,#uid,#ip,#domain,#url,#port,#date,#report-date,#note,#hash,#file type
class CsvParseIndex(IntEnum):
    NO          = 0
    EMPTY       = auto()
    UID         = auto()
    HOST        = auto()
    DOMAIN      = auto()
    URL         = auto()
    PORT        = auto()
    DATE        = auto()
    REPOPT_DATE = auto()
    NOTE        = auto()
    HASH        = auto()
    FILE_TYPE   = auto()

# Class for reading csv file
class CsvParser():
    def __init__(self, filename):
        self._filename: str = filename
        CsvParser.count: int = 0
    
    def validate_file_format(self):
        # check file extension
        if not self._filename[-4:] == ".csv":
            print('ERROR: Set the file extension to ".csv".')
            return False
    
        # read file as csv file
        with open(self._filename, 'r', encoding='utf-8_sig') as f:
            # retrieve header from CSV file
            header = next(csv.reader(f))
        validate = header[CsvParseIndex.NO.value]            == '1'            and \
                   header[CsvParseIndex.EMPTY.value]         == ''             and \
                   header[CsvParseIndex.UID.value]           == '#uid'         and \
                   header[CsvParseIndex.HOST.value]          == '#ip'          and \
                   header[CsvParseIndex.DOMAIN.value]        == '#domain'      and \
                   header[CsvParseIndex.URL.value]           == '#url'         and \
                   header[CsvParseIndex.PORT.value]          == '#port'        and \
                   header[CsvParseIndex.DATE.value]          == '#date'        and \
                   header[CsvParseIndex.REPOPT_DATE.value]   == '#report-date' and \
                   header[CsvParseIndex.NOTE.value]          == '#note'        and \
                   header[CsvParseIndex.HASH.value]          == '#hash'        and \
                   header[CsvParseIndex.FILE_TYPE.value]     == '#file type'
        if not validate:
            print('ERROR: Your column header does not follow the specification.')
            return False
        else:
            return True
    
    def readline(self):
        if not self.validate_file_format():
            print('Aborting.\n')
            exit(1)
        else:
            print('The file format seems good. Proceeding process...')
        
        with open(self._filename, 'rt', encoding='utf-8_sig') as f:
            reader = csv.reader(f)
            # skip the header
            if CsvParser.count_rows() == 0: next(reader)
            for line in reader:
                CsvParser.count += 1
                # skip line with empty UID
                if line[CsvParseIndex.UID.value] == '': continue
                yield line
    # count lines
    @classmethod
    def count_rows(cls):
        return cls.count

# Adapter class for setting destination port
class SourcePortAdapter(HTTPAdapter):
    def __init__(self, port, *args, **kwargs):
        self._source_port = port
        super(SourcePortAdapter, self).__init__(*args, **kwargs)
    
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, 
        block=block, source_address=('', self._source_port))


# Manages of send_ping and send_http
def monitor(host: str, src_port=None, dst_port=80):
    print("Target host:", host)
    s_ping = send_ping(host)
    s_http = send_http(host=host, src_port=src_port, dst_port=dst_port)
    if type(s_http) is None:
        print("\nERROR in send_http")
    else:
        print("\nsend http:", s_http.status_code, s_http.reason)
        s_http = (s_http.status_code, s_http.reason, s_http.raw.version)
    return s_ping, s_http 

# send ping
def send_ping(host, times="4"):
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
    ping = subprocess.run(["ping", opt, times, host], stdout=subprocess.PIPE)
    try:
        print("Sending ping to...", host)
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
def  send_http(host: str, src_port:int=None, dst_port:int=80, header:dict=None):
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
        response = sess.get(query, timeout=(4.0,8.0))
    except requests.ConnectionError:
        print('ERROR: Connection Error')
        return None
    except requests.Timeout:
        print('ERROR: Timeout')
        return None
    return response
