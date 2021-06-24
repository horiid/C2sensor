import configparser, sys, os

class ConfigManager():
    def __init__(self, conf_path, read_default=False, read_monitor=False) -> None:
        self.conf_path = conf_path

        if self.check_file_path():
            self.ini_file = configparser.ConfigParser()
            self.ini_file.read(self.conf_path, encoding='utf-8')
            
            self.read_default = read_default
            self.path_section = 'DEFAULT' if self.read_default else 'STORAGE_PATHS'
            self.abs_path = self.ini_file.get(self.path_section, 'abs_path')
            self.abs_path = os.path.expanduser(self.abs_path)
            self.rel_path = self.ini_file.get(self.path_section, 'rel_path')
            # read from MONITOR_STAT
            self.c2_list, self.port = None, None
            if read_monitor:
                try:
                    self.c2_list = self.ini_file.get('MONITOR_STAT', 'c2_list')
                    self.port    = self.ini_file.get('MONITOR_STAT', 'port')
                except configparser.NoSectionError:
                    print('MONITOR_STAT Section not found')
                except configparser.NoOptionError:
                    print('Option naming for MONITOR_STAT is not correct.')
        else:
            print('Config file Not Found.')
            return
        print('''Configuration of config.ini finished.
STORAGE PATHS:
    ABS: {0}
    REL: {1}
        
MONITOR_STAT:
    C2 LIST: {2}
       PORT: {3}
        '''.format(self.abs_path, self.rel_path, self.c2_list, self.port))

    def check_file_path(self):
        return os.path.exists(self.conf_path)
    
def dump_json():
    pass

def get_path(conf: str, observe_time:str, threat_id:str):
    '''Get a path for storing monitoring results

    Get a path accordingly, referencing observation time and threat ID.
    The directory for storing logs looks like this:
    root/
      ├ THREAT_1/
      |     └2021
      |        ├01
      |        | └2021-01-31T12:00:00.json
      |        | └2021-01-31T16:00:00.json
      |        | └2021-01-31T20:00:00.json
      |        | └...
      |        └02
      |         └...
      ├ THREAT_2/
      |     ├2020
      |     └2021
      ...

    Args:
        root (str): Root of the directory to store logs.
        observe_time (str): observation time in format: "%Y-%m-%dT%H:%M:%S".
        threat_id (str): ID assigned at the CSV file.
    
    Returns:

    '''
    ini_file = configparser.ConfigParser()
    ini_file.read(conf, encoding='utf-8')
    for key, val in ini_file.items():
        print(key, val)
        print(val.name)
    
def path_conf():
    print(os.getcwd())
    print(os.listdir(path='.'))
    conf = 'src/config/config.ini'
    print(os.path.exists('conf'))
    get_path(conf=conf, observe_time="", threat_id="THREAT ABC")
