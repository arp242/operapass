#!/usr/bin/env python
#
# Marin Tournoij <martin@arp242>
# Free for any use, there are no restrictions
#
# This is, in part, based on the information found here:
#   http://securityxploded.com/operapasswordsecrets.php
#

import datetime
import hashlib
import os
import platform
import re
import struct
import sys

import pyDes

def DecryptBlock(key, text):
	# Static salt
	salt = '\x83\x7D\xFC\x0F\x8E\xB3\xE8\x69\x73\xAF\xFF'

	h = hashlib.md5(salt + key).digest()
	h2 = hashlib.md5(h + salt + key).digest()

	key = h[:16] + h2[:8]
	iv = h2[-8:]

	return pyDes.triple_des(key, pyDes.CBC, iv).decrypt(text)

def GetData(pwfile):
	with open(pwfile, 'rb') as fp:
		# Header, mostly 0. On my system (FreeBSD/11.51) 0x3 is set to 0x06, 0x23 to 0x01
		data = fp.read(36)

		ret = []
		data = fp.read(4)
		while True:
			if len(data) < 4:
				return ret

			size_block = struct.unpack('>I', data)[0]
			size_key = struct.unpack('>I', fp.read(4))[0]
			key = struct.unpack('>%ss' % size_key, fp.read(size_key))[0]
			size_data = struct.unpack('>I', fp.read(4))[0]
			data = struct.unpack('>%ss' % size_data, fp.read(size_data))[0]

			ret.append([key, data])

			# There often (but not always) seems to be some amount of zero-padding
			# after this ... The value is often "odd" such as uneven numbers and I
			# can't find a pattern ... This seems to skip/read over it without too
			# much problems ...
			n = []
			while True:
				d = fp.read(1)

				if not d:
					return ret
				n.append(d)

				if d != '' and ord(d) != 255 and ord(d) > 8:
					# Peek 4 bytes ahead, the key lenght is always 8 so we can use this
					# to verify we've got the right number
					pos = fp.tell()
					check = fp.read(4)
					fp.seek(pos)
					if ord(check[-1:]) == 8:
						data = ''.join(n[-4:])
						break

def GetPasswordfile():
	if len(sys.argv) > 1:
		pwfile = sys.argv[1]
	else:
		if sys.platform[:3] == 'win':
			# Windows Vista, 7
			if int(platform.version()[:1]) > 5:
				pwfile = os.path.expanduser('~/AppData/Roaming/Opera/Opera/wand.dat')
			# Windows XP, 2000
			else:
				pwfile = os.path.expanduser('~/Application Data/Opera/Opera/wand.dat')
		# UNIX-like and Linux systems
		else:
			pwfile = os.path.expanduser('~/.opera/wand.dat')

	if not os.path.exists(pwfile):
		print "Password file %s doesn't exist." % pwfile
		sys.exit(1)

	return pwfile

def GetPasswords(pwfile):
	data = GetData(pwfile)

	printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'

	rows = []
	key = None
	row = []
	for key, d in data:
		block = DecryptBlock(key, d)
		# Strip non-printable characters
		# XXX This also strips non-ASCII characters
		block = ''.join([ b for b in block if b in printable ])

		# A new "row" is indicated by a timestamp
		try:
			dt = datetime.datetime(1970, 1, 1)
			dt.strptime(block, '%Y-%m-%dT%H:%M:%SZ')
		except ValueError:
			dt = None

		if dt:
			if len(row) > 2:
				if len(row) % 2 == 0:
					del row[1]
				rows.append(row)
			row = []
		else:
			if block[:5] == '*http':
				http = True
			else:
				http = False

			if len(row) >= 1 and block[:4] == 'http' or block[:5] == '*http':
				if http:
					row.append(block[1:])
					row.append('HTTP Authentication')
					row.append('True')
			else:
				row.append(block)

	if len(row) % 2 == 0:
		del row[1]
	rows.append(row)
	return rows[1:]

def GetPasswordsDict(pwfile):
	passwords = GetPasswords(pwfile)

	ret = []
	for row in passwords:
		dictrow = {
			'url': row[0],
			'fields': {}
		}

		i = 0
		for col in row[1:]:
			if i % 2 == 0:
				key = col
			else:
				dictrow['fields'][key] = col
			i += 1

		ret.append(dictrow)

	return ret
