from pprint import pprint
import http, uuid, sys, json, datetime as dt

# Value class for key: "monitoring"
class MonitoringStat():
    # Set of key names should be immutable
    KEY_SET = frozenset({'input', 'domain_name', 'ipv4_addr', 'file', \
                'files', 'network_traffic', 'ping_ext', \
                'http_request_ext', 'http_response_ext', \
                'observe_time'})
    @classmethod
    def validate(cls, mon: dict):
        '''Return True if key set of given dict is the same or superset of Monitoring.KEY_SET.'''
        return mon.keys() >= cls.KEY_SET
        
    def __init__(self, input: str=None, domain_name: list=None, 
                 ipv4_addr: list=None, file: dict=None, files: list=None,
                 network_traffics: dict=None, ping_ext: dict=None,
                 http_request_ext: dict=None, http_response_ext: dict=None
                 ) -> None:
            self.input        = input
            self.domain_name  = domain_name
            self.ipv4_addr    = ipv4_addr
            self.file         = file
            self.files        = files
            self.network_traffic   = network_traffics
            self.ping_ext          = ping_ext
            self.http_request_ext  = http_request_ext
            self.http_response_ext = http_response_ext
            self.observe_time      = dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    @property
    def monitoring(self):
        '''Return Monitoring Key-Value dict.'''
        return_dict = dict()
        for key in MonitoringStat.KEY_SET:
            return_dict[key.replace('_', '-')] = getattr(self, key)
        return return_dict
    
    @monitoring.setter
    def monitoring(self, mon: dict):
        if MonitoringStat.validate(mon):
            for key, val in mon.items():
                setattr(self, key, val)
        else:
            print('Format does not match with the definition.')

    @staticmethod
    def empty_map():
        empty_map = dict()
        empty_map['input'] = ''
        empty_map['domain_name'] = list()
        empty_map['ipv4_addr'] = list()
        empty_map['file'] = {'file-type': '', 'name': '', 'hashes': \
                 {'md5': '', 'sha1': '', 'sha256': ''}}
        empty_map['files'] = \
            [{'file_type': '', 'name': '', 'md5': '', 'sha1': '', 'sha256': ''}]
        empty_map['network_traffic'] = {'src_port': '', 'dst_port': ''}
        empty_map['ping_ext'] = {'lost': '', 'ttl': 0, 'rtt': ''}
        empty_map['http_request_ext'] = \
            {'request_method': '', 'request_value': '', \
                 'request_version': '', 'request_header': \
                     {'Accept-Encoding': '', 'User-Agent': '', 
                           'Host': ''}}
        empty_map['http_response_ext'] = \
            {'status_code': 0, 'reason_phrase': ''}
        empty_map['observe_time'] = ''
        return empty_map


# Value class for key: "process-time"
class ProcessStat():
    def __init__(self, start: str, end: str) -> None:
        self.sys_name = sys.platform
    @property
    def start(self):
        return self.start
    @start.setter
    def start(self, start):
        self.start = start
    
    @property
    def end(self):
        return self.start
    @end.setter
    def end(self, end):
        self.end = end

# Thrat info expression format based on the definition of ICT-Isac. 
class X_ICT_Isac_Cti():
    def __init__(self, submit_time: str=None, proc: ProcessStat=None, mon: MonitoringStat=None) -> None:
        self.id = str(uuid.uuid4())
        self.submit_time = submit_time
        self.__monitoring = mon
        self.__process_time = proc
        self.__schema = dict({'x-ict-isac.jp': {"id": self.id}})
        self.__schema['submit_time'] = self.submit_time
        
        if proc is None: self.__schema['x-ict-isac.jp']['monitoring'] = mon.__dict__
        self.__schema['x-ict-isac.jp']['process-time'] = proc.__dict__
    @property
    def schema(self):
        return self.__schema
    @property
    def monitoring(self):
        # return self.__monitoring if the attribute is not None or return empty monitoring map 
        return_map = MonitoringStat.empty_map() if self.__monitoring is None else self.__monitoring
        return return_map
    @property
    def process_time(self):
        return self.__process_time

    @schema.setter
    def schema(self, schema):
        self.__schema = schema
    @monitoring.setter
    def monitoring(self, mon):
        pass
    @process_time.setter
    def process_time(self, proc):
        pass
    
def main():
    monstat = MonitoringStat()
    pprint(monstat.monitoring)
    monstat.monitoring = monstat.empty_map()
    print()
    pprint(monstat.monitoring)
if __name__ == '__main__':
    main()