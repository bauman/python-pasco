# python-pasco
parse IE history (index.dat) files with python


#LICENSE
BSD 3-Clause

Copyright (C) 2003, by Keith J. Jones.

Copyright (C) 2016, by Dan Bauman. (Python Generator Code)

Original Source Download.

https://sourceforge.net/projects/fast/files/Pasco/Pasco%20v20040505_1/pasco_20040505_1.zip/download


#Usage

``` python
    ip = pasco.IndexParser()
    for match in ip.parse(filename):
        if match:
            pprint(match)
```

to yield double-bar delimited format, use "ascsv" option

``` python
    ip = pasco.IndexParser()
    for match in ip.parse(filename, ascsv=True):
        if match:
            pprint(match)
```
