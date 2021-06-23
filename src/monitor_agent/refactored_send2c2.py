import argparse, datetime, pprint, sys, os
sys.path.append("../")

from monitor_agent.csvutils import CsvParser
from monitor_agent.monitorutils import monitoring_stat
from models.schema import ProcessStat, X_ICT_Isac_Cti

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
    
    # list of threats in csv file
    rows = CsvParser(filename=args.c2list)
    for row in rows.readline():
        monitoring_stat(row, observe_time)

if __name__ == '__main__':
    main()
