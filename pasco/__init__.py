import pascohelper
from tempfile import NamedTemporaryFile
import os
class IndexParser(object):
    def __init__(self):
        self.delimiter = "||" #from pascohelpermodule.c
        self.headers="type||url||modified_time||access_time||filename||directory||http_headers".split(self.delimiter)
        return None
    def parse(self, indexfile):
        generator = pascohelper.iterparse( indexfile )
        for line in generator:
            if line:
                line = line.split(self.delimiter)
                yield self.make_dict(self.headers, line)
        return
    def make_dict(self, headers, line):
        result = {}
        try:
            for i in range(len(headers)):
                result[headers[i].strip()] = line[i].strip()
        except IndexError:
            result = None
        return result
