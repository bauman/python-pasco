import pascohelper
from tempfile import NamedTemporaryFile
import os
class IndexParser(object):
    def __init__(self):
        return None
    def parse(self, indexfile):
        return_file = "%s.out" %(indexfile)
        try:
            with open(return_file, 'a') as f:
                f.seek(0)
        except IOError:
            with NamedTemporaryFile() as f:
                return_file = f.name
        return_file = pascohelper.mainparse(indexfile, return_file )
        try:
            with open(return_file, 'rb') as f:
                headers = f.readline().strip().split("||")
                line = f.readline().strip().split("||")
                while line:
                    yield self.make_dict(headers, line)
                    line = f.readline().strip().split("||")
                    if len(line) == 1:
                        break
        finally:
            os.unlink(return_file)
        return
    def make_dict(self, headers, line):
        result = {}
        try:
            for i in range(len(headers)):
                result[headers[i].strip()] = line[i].strip()
        except IndexError:
            result = None
        return result
