operapass
=========

Opera is a great browser, but one feature it's been lacking for a very long
time is the ability to view the passwords you've saved with the Opera password
manager ("The wand"). 

There are a few closed-source and Windows-only programs out there. An
open-source multi-platform utility to read the wand seemed like a good idea :-) 

operapass can be run from in a terminal or with a basic GUI. It should find the
wand.dat in your Opera profile directory, but you can also specify it as the
first parameter (i.e. operapass-tk path/to/wand.dat 

There are two utilities: operapass-dump to dump the password file to your
stdout (i.e. terminal) and operapass-tk for a very basic TKinter GUI. 

It should run on Windows, Linux, FreeBSD, and OSX.

Notes
-----
operapass can currently *only read wand files without a master password*. Note
you can remove and (re-)add a master password at any time in the Opera
preferences. 

operapass will use the M2Crypto module when available, and fall back to pyDes
(bundled) when it's not. Note that M2Crypto is *much* faster.

Credits
-------
Copyright © 2011-2012, Martin Tournoij <martin@arp242.net>
MIT licence applies: http://opensource.org/licenses/MIT
http://code.arp242.net/operapass

The Opera wand format is described here:
http://securityxploded.com/operapasswordsecrets.php
This information was an extremely useful starting point. 

operpass also includes pyDes from http://twhiteman.netfirms.com/des.html 

Status
------
Should work with most password files, but sometimes there's "junk" in the
password file. It looks like Opera just ignores this.

