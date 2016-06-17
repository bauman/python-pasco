#!/bin/bash

sudo yum remove python-pasco -y
rm -rf build/ dist/
python setup.py bdist_rpm
sudo yum -y localinstall dist/python-pasco-0.1.1-1.x86_64.rpm
rm -rf /tmp/dan.out1

