import argparse, datetime, sys, os
from pprint import pprint
from concurrent.futures import ThreadPoolExecutor
sys.path.append("../")

from monitor_agent.csvutils import CsvParser
from monitor_agent.monitorutils import monitoring_stat
from models.schema import ProcessStat, X_ICT_Isac_Cti

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
    parser = argparse.ArgumentParser(description="Monitor agent for sending ping and http request")
    parser.add_argument('c2list', help="CSV file showing lists of C2 servers")
    parser.add_argument('--port', type=int, default=80, help="Specify destination port number. HTTP_ by default.")
    args = parser.parse_args()

    # get the executed time and set it to the filename
    observe_time = datetime.datetime.now()
    observe_time = observe_time.strftime('%Y-%m-%dT%H:%M:%S')
    print("Observed at:", observe_time, "\n")
    
    # Execute monitoring concurrently.
    # monitoring_stat() can be executed one by one, but it requires network I/O,
    # hense, it will be much slower compared to concurrent execution.
    rows = CsvParser(filename=args.c2list)
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="Server") as executor:
        results = executor.map(monitoring_stat, [row for row in rows.readline()])
    for result in results:
        pprint(result.monitoring, width=40)
        print()

if __name__ == '__main__':
    main()
