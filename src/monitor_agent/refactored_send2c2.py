import argparse, datetime, sys, os
import json
from pprint import pprint
from concurrent.futures import ThreadPoolExecutor

from monitor_agent.loggers import get_path
sys.path.append(os.pardir)

from monitor_agent.csvutils import CsvParser
from monitor_agent.monitorutils import monitor, monitoring_stat
from models.schema import ProcessStat, X_ICT_Isac_Cti
from monitor_agent import configutils

def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print('''
   ____  ____    ____                                 
  / ___||___ \  / ___|   ___  _ __   ___   ___   _ __ 
 | |      __) | \___ \  / _ \| '_ \ / __| / _ \ | '__|
 | |___  / __/   ___) ||  __/| | | |\__ \| (_) || |   
  \____||_____| |____/  \___||_| |_||___/ \___/ |_|
    ''')

# timer program execution for process-time
def process_timer(row: list):
    start = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    monitor = monitoring_stat(row)
    end = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    return ProcessStat(start=start, end=end), monitor

def main():
    print_banner() 

    # parse arguments
    parser = argparse.ArgumentParser(description="Monitor agent for sending ping and http request.")
    parser.add_argument('--c2list', type=str, help="CSV file showing lists of C2 servers.")
    parser.add_argument('--port', type=int, default=80, help="Specify destination port number. HTTP_ by default.")
    parser.add_argument('-S', '--save-logs', action='store_true', help='Save monitor logs to the directory addressed in config.ini.')
    parser.add_argument('-D', '--read-default', action='store_true', help='read default configuration from config.ini.')
    parser.add_argument('-M', '--read-monitor', action='store_true', help='read monitoring configuration from config.ini.')
    args = parser.parse_args()

    config_ini = "src/config/config.ini"
    config = configutils.ConfigManager(conf_path=config_ini, 
                                       read_default=args.read_default,
                                       read_monitor=args.read_monitor,
                                       save_logs=args.save_logs)
    # if neither config.ini nor argument specifies csv file, then abort.
    if config.c2_list is not None:
        threatCSV = config.c2_list
    elif args.c2list is not None:
        threatCSV = args.c2list
    else:
        print('Neither config.ini nor the argument specifies threat list CSV file. Aborting.')
        exit()
    # get the executed time and set it to the filename
    observe_time = datetime.datetime.now()
    observe_time = observe_time.strftime('%Y-%m-%dT%H:%M:%S')
    print("Observing at:", observe_time)
    print('C2 list     :', threatCSV, "\n")
    # Concurrent processing for network I/O
    # monitoring_stat() can be executed linearly but it does network I/O,
    # hense, it will be much slower compared to run it concurrently.
    rows = CsvParser(filename=threatCSV)
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="Server") as executor:
        results = executor.map(process_timer, [row.encode('utf-8') for row in rows.readline()])
    
    # See results
    for result in results:
        # if save_logs flag is set, save results
        if config.save_logs:
            cti = X_ICT_Isac_Cti(result[0].start, result[0], result[1])
            storage_path = get_path(path=config.path,
                                    threat_id=result[1].threat_id,
                                    observe_time=result[0].start,
                                    filename=result[0].start,
                                    uuid=cti.id,
                                    create_path=True)
            if storage_path is None:
                continue
            print(storage_path)
            with open(storage_path, "w", encoding='utf-8') as outf:
                json.dump(cti.schema, outf, indent=4)
        print(result[1].threat_id)
        pprint(result[1].http_response_ext, width=40)
        print()

