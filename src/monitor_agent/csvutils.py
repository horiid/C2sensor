from enum import IntEnum, auto
import csv

# Index for reading CSV file
# No,,#uid,#ip,#domain,#url,#port,#date,#report-date,#note,#hash,#file type
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
    """Parser for formatted CSV

    CsvParser is a parser class of threat CSV.

    Attributes:
        _filename (str): filename of the target CSV file.
        count (int): counter for CSV rows. 
    """
    def __init__(self, filename):
        self._filename: str = filename
        CsvParser.count: int = 0
    
    def validate_file_format(self):
        '''Validate the CSV file.

        validate_file_format() validates whether "_filename" file complies with the columns given by CsvParserIndex enum.
        
        Args:
            None.
        
        Returns:
            True: returns True if the file complies with the column headers and file extension ends with ".csv".
            False returns False if the file does not satisfy the conditions specified above.
        '''
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
        '''Returns a row one by one

        readline() returns a row of the CSV file selected by "_filename" one by one.
                   Hence, this function is a generator class.

        Args:
            None.

        Returns:
            list: returns list, which is a row of the CSV file. Note that it ignores the first row(header).
        '''
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
        '''Counts rows have been read

        count_rows() returns number of rows have been read by readline() so far.
                     This function is a classmethod. 

        Args:
            None.
        
        Returns:
            int: number of rows have been read.
        '''
        return cls.count