import argparse, datetime, pprint, json, sys
sys.path.append("../")
from json.decoder import JSONDecodeError, JSONDecoder
from .monitorutils import CsvParser, monitor
from .monitorutils import CsvParseIndex as csvidx
from models.schema import ProcessStat, MonitoringStat, X_ICT_Isac_Cti
from random import randint

def dump_cti_json(mon: MonitoringStat=None):
    if mon is None:
        mon = MonitoringStat.empty_map()
        json.dump(mon)
        
    pass


def main():
    HTTP_ = 80
    HTTPS_ = 443
    # parse arguments
    parser = argparse.ArgumentParser(description="Monitor agent for sending ping and http request")
    parser.add_argument('c2list', help="CSV file showing lists of C2 servers")
    parser.add_argument('port', type=int, help="Specify destination port number. HTTP_ by default.")
    args = parser.parse_args()

    # get the executed time and set it to the filename
    observe_time = datetime.datetime.now()
    observe_time = observe_time.strftime('%Y-%m-%dT%H:%M:%S')
    print("Observed at:", observe_time, "\n")
    
    # list of threats in csv file
    rows = CsvParser(filename=args.c2list)
    for row in rows.readline():
        # prepare HTTP header for send_http()
        req_header = {"Accept-Encoding": "gzip,deflate", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36",
        "Host": ""}
        # get data from row for Monitoring class initialization
        if row[csvidx.DOMAIN]:
            # domain name e.g. example.com
            input = row[csvidx.DOMAIN]
            req_header['Host'] = input
        elif row[csvidx.URL]:
            # ignore schema e.g. http, https, ftp.
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
        # parse row[file type] and if there are multiple files, store data to 'files'
        is_file_single = False
        file_list = row[csvidx.FILE_TYPE].split(',')
        print("file list: {}".format(file_list))
        if len(file_list) == 1 and file_list[0] != '': is_file_single = True
        print("is_file_single:", is_file_single)
        # do file count processing here


        # Get hashes
        hashes = row[csvidx.HASH]
        try:
            json_decoder = JSONDecoder()
            hashes, i= json_decoder.raw_decode(hashes)
            if i in locals(): del i
        except JSONDecodeError:
            pass # if there's no hashes, just pass.
        # Preprocessing for  sending data to C2 servers
        src_port = randint(49152, 65535)
        dst_port = None
        # PORT is empty
        if row[csvidx.PORT] == '':
            dst_port = HTTP_
        # PORT has multiple port number
        elif "," in row[csvidx.PORT]:
            dst_port = dst_port.split(',')
            if "443" in dst_port:
                dst_port = HTTPS_
            else:
                dst_port = HTTP_
        else:
            dst_port = HTTP_
                
        network_traffic = {'src-port': src_port, 'dst-port': dst_port}
        # send ping and http GET method
        ping, http_ext = monitor(host=input, src_port=src_port, dst_port=dst_port)
        print(ping, http_ext)

        http_version = ''
        http_response_ext = {'status_code': '', 'reason_phrase': ''}
        # Received HTTP response
        if type(http_ext) is not None:
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
        monitor_ = MonitoringStat()
        # Append data to MonitoringStat instance
        monitor_.input = input
        monitor_.domain_name = domain_name
        monitor_.ipv4_addr = ipv4_addr
        monitor_.observe_time = observe_time
        monitor_.network_traffic = network_traffic
        monitor_.ping_ext = ping
        monitor_.http_request_ext = http_request_ext
        monitor_.http_response_ext = http_response_ext

        # monitor_['file']
        # monitor_['files']
        pprint.pprint(monitor_.monitoring)

if __name__ == '__main__':
    main()
