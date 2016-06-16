__author__ = 'dan'
#!/usr/bin/python


from distutils.core import setup, Extension

module1 = Extension('pascohelper', #TODO: Figure out how to deploy this lib inside bsonsearch package
                    sources = ['pasco/pascohelpermodule.c'],
                    libraries=[],
                    include_dirs=[])

setup (name = 'python-pasco',
        version = '0.1.1',
        description = 'parse index.dat',
        maintainer = "Dan Bauman",
        packages=["pasco"],
        ext_modules = [module1]
       )