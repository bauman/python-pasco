#!/bin/bash

sudo yum remove python-pasco -y
rm -rf build/ dist/
python setup.py bdist_rpm
sudo yum -y localinstall dist/python-pasco-0.1.1-1.x86_64.rpm
rm -rf /tmp/dan.out1

#python -c "import pascohelper; print pascohelper.iterparse('/tmp/tmpr41Td2/support.CITRIX/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat');"
python -c "import pascohelper; print pascohelper.mainparse('/tmp/tmpr41Td2/mlevoy/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat', '/tmp/dan.out1' );"