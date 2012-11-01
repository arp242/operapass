import glob
import sys

from distutils.core import setup

setup(
	name = 'operapass',
	version = '1.1',
	author = 'Martin Tournoij',
	author_email = 'martin@arp242.net',
	url = 'http://code.arp242.net/operapass',
	scripts = ('operapass-dump', 'operapass-tk'),
	packages = ('operapass',),
	#data_files = (),
)
