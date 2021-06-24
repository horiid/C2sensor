import argparse, datetime, sys, os
from pprint import pprint
from concurrent.futures import ThreadPoolExecutor
sys.path.append(os.pardir)

from monitor_agent.csvutils import CsvParser
from monitor_agent.monitorutils import monitoring_stat
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

    config = configutils.ConfigManager("src/config/config.ini", read_default=args.read_default, read_monitor=args.read_monitor)
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
    print("Observed at:", observe_time)
    print('C2 list    :', threatCSV, "\n")
    # Execute monitoring concurrently.
    # monitoring_stat() can be executed one by one, but it requires network I/O,
    # hense, it will be much slower compared to concurrent execution.
    rows = CsvParser(filename=threatCSV)
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="Server") as executor:
        results = executor.map(monitoring_stat, [row for row in rows.readline()])
    
    # See results
    for result in results:
        pprint(result.monitoring, width=40)
        print()

