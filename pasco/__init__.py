import pascohelper
class IndexParser(object):
    def __init__(self):
        self.delimiter = "||" #from pascohelpermodule.c
        self.headers="type||url||modified_time||access_time||filename||directory||http_headers||invalid_record_len".split(self.delimiter)
        return None
    def parse(self, indexfile, ascsv=False):
        if ascsv:
            yield self.delimiter.join(self.headers)
        generator = pascohelper.iterparse( indexfile )
        for line in generator:
            if line:
                if ascsv:
                    yield line
                else:
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
