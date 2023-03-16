import configparser, os

class ConfigManager():
    def __init__(self, conf_path, read_default=False, save_logs=True) -> None:
        self.conf_path = conf_path
        self.save_logs = save_logs

        if self.check_file_path():
            self.ini_file = configparser.ConfigParser()
            self.ini_file.read(self.conf_path, encoding='utf-8')

            self.path_section = 'DEFAULT_PATHS' if read_default else 'STORAGE_PATHS'
            self.path = self.ini_file.get(self.path_section, 'path')
            self.path = os.path.expanduser(self.path)
            self.agent_name = self.ini_file.get('AGENT_NAME', 'agent_name')
            self.box_auth = self.ini_file.get('BOX_AUTH', 'box_auth')

            # read from MONITOR_STAT
            self.c2_list, self.port = None, None

            try:
                self.c2_list = self.ini_file.get('MONITOR_STAT', 'c2_list')
                self.port    = self.ini_file.get('MONITOR_STAT', 'port')
                print(self.c2_list, self.port)
            except configparser.NoSectionError:
                print('MONITOR_STAT Section not found')
            except configparser.NoOptionError:
                print('Option naming for MONITOR_STAT is not correct.')
        else:
            print('Could not find config file. Aborted.')
            exit()
        print('''Configuration of config.ini finished.
STORAGE PATH: {0}        
MONITOR_STAT:
    C2 LIST: {1}
       PORT: {2}
        '''.format(self.path, self.c2_list, self.port))

    def check_file_path(self):
        return os.path.exists(self.conf_path)
