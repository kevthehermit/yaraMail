#!/usr/bin/env python
'''
Copyright (C) 2012-2013 Kevin Breen.
YaraMail
Python script to YaraScan Email Attatchments
'''
__description__ = 'Yara Mail Scanner, use it to Scan Email Attatchments'
__author__ = 'Kevin Breen'
__version__ = '0.0.1'
__date__ = '2013/04/20'


import os
import sys
import time
import tempfile
import shutil
import email.utils
import mimetypes
from optparse import OptionParser, OptionGroup
try:
	import yara
except:
	print "Failed to Import Yara"

def main():
	parser = OptionParser(usage='usage: %prog [options] smtpFile | imap Folder Name\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-r", "--Rules", dest="yaraRule",
                  help="Yara Rule File", metavar="FILE")
	parser.add_option("-e", "--extract", action='store_true', default=False, help="Extract Files if Zip Archive detected Deafult is No")
	group = OptionGroup(parser, "IMAP OPTIONS")
	group.add_option("-u", "--user", type="string", help="IMAP UserName")
	group.add_option("-p", "--passwd", type="string", help="IMAP Password")				  
	group.add_option("-s", "--server", type="string", help="IMAP ServerName")

	parser.add_option_group(group)
	(options, args) = parser.parse_args()
	global tmpDir
	tmpDir = tempfile.mkdtemp()
	global extract
	extract = options.extract
	if len(args) != 1:
		parser.print_help()
	elif options.user:
		imapScan(args[0], options.user, options.passwd, options.server, options.yaraRule)
	else:
		smtpScan(args[0], options.yaraRule)
	shutil.rmtree(tmpDir)


class attExtract:
	def __init__(self, emailFile, yaraRule):
		x = open(emailFile)
		msg = email.message_from_file(x)
		x.close()
		# Grab some references so we can identify the email later
		subjectLine = msg['subject']
		fromAdd = msg['from']
		# taken from the python docs tut
		counter = 1
		print extract
		for part in msg.walk():
			if part.get_content_maintype() == 'multipart':
				continue
			filename = part.get_filename()
			
			if not filename:
				ext = mimetypes.guess_extension(part.get_content_type())
				if not ext:
					ext = '.bin'
				filename = 'part-%03d%s' % (counter, ext)
			counter += 1
			fp = open(os.path.join(tmpDir, filename), 'wb')
			fp.write(part.get_payload(decode=True))
			fp.close()
			ext = filename.split(".")[-1]
			if ext == 'zip' and extract == True:
				from zipfile import ZipFile
				with ZipFile(os.path.join(tmpDir, filename)) as compressed:
					for member in compressed.namelist():
						filename = os.path.basename(member)
						if not filename:
							continue
						source = compressed.open(member)
						dest = file(os.path.join(tmpDir, filename), "wb")
						with source, dest:
							shutil.copyfileobj(source, dest)
							print "Scanning %s" % filename
						yaraScan(filename, yaraRule)
			else:
				print "Scanning %s" % filename
				yaraScan(os.path.join(tmpDir, filename), yaraRule)				
		
		

		
class smtpScan:
	def __init__(self, emailFile, yaraRule):
		attExtract(emailFile, yaraRule)


		
class imapScan:
	def __init__(self, inbox, user, pwd, server, yaraRule):
		import imaplib
		print tmpDir		
		m = imaplib.IMAP4_SSL(server)
		m.login(user,pwd)
		m.select(inbox)
		resp, items = m.search(None, "ALL") # IMAP Filter Rules here
		items = items[0].split()
		count = len(items)
		counter = 0
		for emailid in items:
			emailFile = os.path.join(tmpDir, inbox+emailid + ".txt")
			counter +=1
			resp, data = m.fetch(emailid, "(RFC822)")
			email_body = data[0][1]
			msgFile = open(emailFile, "w")
			msgFile.write(email_body)
			msgFile.close()
			print "Processing %s" % emailFile
			attExtract(emailFile, yaraRule)
	
class yaraScan:
	def __init__(self, scanfile, yaraRule):
		yaraRules = yara.compile(yaraRule)
		matches = []
		if os.path.getsize(scanfile) > 0:
			for match in yaraRules.match(scanfile):
				matches.append({"name" : match.rule, "meta" : match.meta})
		for m in matches:
			yaraRule = m["name"]
			try:
				yaraDesc = m["meta"]["maltype"]
			except:
				yaraDesc = None
		print matches
		
		
if __name__ == "__main__":
	main()