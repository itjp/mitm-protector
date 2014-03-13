#!/usr/bin/python3

from distutils.core import setup

setup(name='mitm-protector',
      version='1.0',
      description='MITM-protector - protect\'s you from any kind of MITM-attacks, arpspoofing, ettercap, sslstrip, droidsheep, zAnti, dsploit, etc.',
      license='GPL3+',
      author='Jan Helbling',
      author_email='jan.helbling@gmail.com',
      url='http://jan-helbling.no-ip.biz/',
      scripts=['bin/mitm-protector.py']
)
