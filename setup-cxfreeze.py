from distutils.core import setup
from cx_Freeze import setup, Executable

setup(
	name = 'operapass',
	version = '1.2',
	author = 'Martin Tournoij',
	author_email = 'martin@arp242.net',
	url = 'http://code.arp242.net/operapass',
	scripts = ('operapass-dump', 'operapass-tk'),
	packages = ('operapass',),
	#data_files = (),

	options = {
		'build_exe': {
			'excludes': ['_ssl', '_hashlib', '_ctypes', 'bz2', 'email', 'unittest', 'doctest',
				'optparse', '_socket', 'pyexpat'],
		}
	},
	executables = [
		Executable(
			script = 'operapass-dump',
			compress = True,
			#icon = './data/icons/icon.ico',
		),
		Executable(
			script = 'operapass-tk',
			base = 'Win32GUI',
			compress = True,
			#icon = './data/icons/icon.ico',
		),
	]

)
