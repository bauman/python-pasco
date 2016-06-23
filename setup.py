__author__ = 'dan'
#!/usr/bin/python


from distutils.core import setup, Extension

module1 = Extension('pascohelper',
                    sources = ['pasco/pascohelpermodule.c'],
                    libraries=[],
                    include_dirs=[])

setup (name = 'python-pasco',
        version = '0.1.1',
        description = 'parse index.dat',
        maintainer = "Dan Bauman",
        maintainer_email="dan@bauman.space",
        download_url = 'https://github.com/bauman/python-pasco/archive/0.1.1-2.tar.gz',
        url="https://github.com/bauman/python-pasco",
        packages=["pasco"],
        ext_modules = [module1]
       )