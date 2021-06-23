import argparse, datetime, pprint, json, sys, os
sys.path.append("../")

from json.decoder import JSONDecodeError, JSONDecoder
from monitor_agent.monitorutils import monitor
from monitor_agent.csvutils import CsvParser, CsvParseIndex as csvidx
from models.schema import ProcessStat, MonitoringStat, X_ICT_Isac_Cti
from random import randint

def print_banner():
    clear_cmd = "cls" if os.name == "nt" else "clear"
    os.system(clear_cmd)
    print('''
   ____  ____    ____                                 
  / ___||___ \  / ___|   ___  _ __   ___   ___   _ __ 
 | |      __) | \___ \  / _ \| '_ \ / __| / _ \ | '__|
 | |___  / __/   ___) ||  __/| | | |\__ \| (_) || |   
  \____||_____| |____/  \___||_| |_||___/ \___/ |_|
    ''')

def print_threat_id(_id):
    print('''
\n==========================
Threat ID: {0}
==========================
'''.format(_id))

def main():
    print_banner()
    
    # HTTP/HTTPS known ports
    HTTP_ = 80
    HTTPS_ = 443

    # parse arguments
    parser = argparse.ArgumentParser(description="Monitor agent for sending ping and http request")
    parser.add_argument('c2list', help="CSV file showing lists of C2 servers")
    parser.add_argument('--port', type=int, default=HTTP_, help="Specify destination port number. HTTP_ by default.")
    args = parser.parse_args()

    # get the executed time and set it to the filename
    observe_time = datetime.datetime.now()
    observe_time = observe_time.strftime('%Y-%m-%dT%H:%M:%S')
    print("Observed at:", observe_time, "\n")
    
    # list of threats in csv file
    rows = CsvParser(filename=args.c2list)
    for row in rows.readline():
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
            continue
        input = input.replace('[', '').replace(']', '')

        domain_name = [row[csvidx.DOMAIN].replace('[', '').replace(']', '')]
        ipv4_addr = [row[csvidx.HOST].replace('[', '').replace(']', '')]
        
        # Get hashes
        hashes = row[csvidx.HASH]
        try:
            # if #hash is not subscriptable, raise KeyError and exit.
            if  hashes != "" and "{" not in hashes:
                raise KeyError
            json_decoder = JSONDecoder()
            hashes, i= json_decoder.raw_decode(hashes)
            if i in locals(): del i
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
        mal_file = {"file-type": "", "name": "", "hashes": {"md5":"", "sha1": "", "sha256": ""}}
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
        elif file_cnt > 1:
            mal_file = {"file-type": "", "name": "", "hashes": {"md5":"", "sha1": "", "sha256": ""}}

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
                print(row[csvidx.PORT], "is not proper port number.")
                dst_port = HTTP_
        # Send ping & HTTP "GET" request
        network_traffic = {'src-port': src_port, 'dst-port': dst_port}
        ping, http_ext = monitor(host=input, src_port=src_port, dst_port=dst_port, http_headers=req_header)
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
            # else it is unknown.
        
        try:
            req_value = row[csvidx.URL].split('//',1)[1].split('/', 1)[1]
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

if __name__ == '__main__':
    main()
