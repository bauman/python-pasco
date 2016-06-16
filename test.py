import pascohelper
r = pascohelper.iterparse('/tmp/tmpr41Td2/support.CITRIX/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat')

for x in r:
    if x:
        print x