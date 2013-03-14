#!/usr/bin/env python
# encoding=utf-8
#
# Copyright © 2011-2013, Martin Tournoij <martin@arp242.net>
# See below for full copyright
#
# http://code.arp242.net/operapass
#
# This is, in part, based on the information found here:
#   http://securityxploded.com/operapasswordsecrets.php
#

from __future__ import print_function
import datetime
import hashlib
import os
import platform
import re
import struct
import sys

# Try to use m2crypto, this is *much* faster than the pure python pyDes, but
# not as portable
try:
	import M2Crypto
	_fastdes = True
except ImportError:
	#import pyDes
	from . import pyDes
	print('M2Crypto module not found, falling back to pyDes.')
	print('Note this is *much* slower and may take up to a minute or more!')
	_fastdes = False


def DecryptBlock(key, text):
	# Static salt
	salt = b'\x83\x7D\xFC\x0F\x8E\xB3\xE8\x69\x73\xAF\xFF'

	# Master password notes:
	#
	# This *only* encrypts pasword fields, not username/etc. fields.
	# According to http://nontroppo.org/test/Op7/FAQ/opera-users.html#wand-security
	# "if you do use a master password, the used password is a combination of the
	# master password and a 128-byte random portion created at the same time.
	# This random portion is stored outside wand.dat, also encrypted with the
	# master password."
	# Random portion mentioned seems to be opcert6.dat
	#
	# According to http://my.opera.com/community/forums/topic.dml?id=132880
	# "opcert6.dat contains all private keys you have created and the associated
	# client certificates you have requested and installed. The private keys are
	# protected by the security password. [...] A small block of data in the
	# opcert6.dat file is also used when you secure the wand and mail passwords
	# with the security password."

	h = hashlib.md5(salt + key).digest()
	h2 = hashlib.md5(h + salt + key).digest()

	key = h[:16] + h2[:8]
	iv = h2[-8:]

	if not (len(text) / 8.0 % 8).is_integer():
		return '** INVALID **'

	if _fastdes:
		return M2Crypto.EVP.Cipher(alg='des_ede3_cbc', key=key, iv=iv, op=0,
			padding=0).update(text)
	else:
		return pyDes.triple_des(key, pyDes.CBC, iv).decrypt(text)


def RemoveNonprintable(text):
	""" Remove non-printable characters.
	Note we expect a bytes() as text and return a str()! """

	rm = ''
	for i in range(0, 32):
		rm += chr(i)
	rm += chr(127)

	new = ''
	if sys.version_info[0] >= 3:
		rm = bytes(rm, 'utf-8')
		for b in text:
			if b not in rm:
				new += chr(b)
	else:
		rm = bytes(rm)
		for b in text:
			if b not in rm:
				new += b

	return new


def GetData(pwfile):
	fsize = os.stat(pwfile).st_size

	with open(pwfile, 'rb') as fp:
		# Header, mostly 0. On my systems (FreeBSD&Win/11.51) 0x3 is set to 0x06,
		# 0x23 to 0x01
		# If offset 0x07 is set to 1, is seems to flag that a master pw is set
		# TODO ^ Verify this, add detection
		data = fp.read(36)

		ret = []
		data = fp.read(4)
		while True:
			#print(type(data), len(data), data)
			if len(data) < 4:
				# Nowhere near the end, assume "overlapping" of data
				if fsize - fp.tell() > 30:
					diff = 4 - len(data)
					data = ('\x00' * diff) + data
				else:
					#print('ret at line 57', fp.tell())
					return ret

			try:
				before = fp.tell()
				size_block = struct.unpack('>I', data)[0]
				size_key = struct.unpack('>I', fp.read(4))[0]
				key = struct.unpack('>%ss' % size_key, fp.read(size_key))[0]
				size_data = struct.unpack('>I', fp.read(4))[0]
				#print(hex(size_data))
				data = struct.unpack('>%ss' % size_data, fp.read(size_data))[0]

				ret.append([key, data])
			except:
				raise
				#print('passing...', fp.tell(), sys.exc_info()[1])
				fp.seek(before)
				pass

			# There often (but not always) seems to be some amount of zero-padding
			# after this ... The value is often "odd" such as uneven numbers and I
			# can't find a pattern ... This seems to skip/read over it without too
			# much problems ...
			n = []
			while True:
				d = fp.read(1)
				#print(hex(ord(d)), end='')

				if not d:
					#print('ret at line 80', fp.tell())
					return ret
				n.append(d)

				if d != '' and ord(d) != 255 and ord(d) > 8:
					# Peek 4 bytes ahead, the key lenght is always 8 so we can use this
					# to verify we've got the right number
					pos = fp.tell()
					check = fp.read(4)
					if len(check) < 4:
						return ret
					fp.seek(pos)
					#if (ord(check[3:4]) == 8):
					#print('__', ord(check[0:1]), '__', end='')
					#print('__', ord(check[1:2]), '__', end='')
					#print('__', ord(check[2:3]), '__', end='')
					#print('__', ord(check[3:4]), '__')
					if (ord(check[0:1]) == 0 and ord(check[1:2]) == 0
							and ord(check[2:3]) == 0 and ord(check[3:4]) == 8):

						#n = [ chr(ord(a)) for a in n ]
						#data = ''.join(n[-4:])
						data = bytes()
						try:
							for i in range(0, 4):
								data += n[i]
						except IndexError:
							pass
						#print('BR %s, %s\n' % (fp.tell(), len(ret)))
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
		print("Password file %s doesn't exist." % pwfile)
		sys.exit(1)

	return pwfile


def GetPasswords(pwfile):
	data = GetData(pwfile)

	rows = []
	key = None
	row = []
	for key, d in data:
		block = DecryptBlock(key, d)
		block = RemoveNonprintable(block)
		#print(type(block), block)

		# A new "row" is indicated by a timestamp
		try:
			dt = datetime.datetime(1970, 1, 1)
			dt.strptime(block, '%Y-%m-%dT%H:%M:%SZ')
		except ValueError:
			dt = None

		if dt:
			if len(row) > 2:
				if len(row) % 2 == 1:
					del row[1]

				if len(row) > 2:
					rows.append(row[:-1])
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

	if len(row) > 5:
		rows.append(row[:-1])
	rows = rows[1:]

	i = 0
	for row in rows:
		if 'HTTP Authentication' in row:
			rows[i] = [
				row[0],
				'HTTP Authentication', 'True',
				'Username', row[3],
				'Password', row[4],
			]
		i += 1

	return rows


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


# The MIT License (MIT)
#
# Copyright © 2011-2013 Martin Tournoij
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# The software is provided "as is", without warranty of any kind, express or
# implied, including but not limited to the warranties of merchantability,
# fitness for a particular purpose and noninfringement. In no event shall the
# authors or copyright holders be liable for any claim, damages or other
# liability, whether in an action of contract, tort or otherwise, arising
# from, out of or in connection with the software or the use or other dealings
# in the software.
