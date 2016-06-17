__author__ = 'dan'
#import pascohelper
#print pascohelper.mainparse('/tmp/tmpr41Td2/support.CITRIX/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat', '/tmp/dan.out3' )

from sys import argv
from pprint import pprint
import pasco

if len(argv) == 1:
    filename = ''
else:
    filename = argv[1]
ip = pasco.IndexParser()
for match in ip.parse(filename):
    if match:
        pprint(match)

for match in ip.parse(filename, ascsv=True):
    if match:
        pprint(match)