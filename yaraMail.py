#!/usr/bin/env python
'''
Copyright (C) 2012-2013 Kevin Breen.
YaraMail
Python script to YaraScan Email Attatchments
'''
__description__ = 'Yara Mail Scanner, use it to Scan Email Attatchments'
__author__ = 'Kevin Breen'
__version__ = '0.0.2'
__date__ = '2013/04/20'


import os
import sys
import tempfile
import shutil
import email.utils
import mimetypes
from optparse import OptionParser, OptionGroup
try:
	import yara
except:
	print "Failed to Import Yara"
	sys.exit()

def main():
	parser = OptionParser(usage='usage: %prog [options] rulefile smtpFile|server Address\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-e", "--extract", action='store_true', default=False, help="Extract Files if Zip Archive detected Deafult is No")
	parser.add_option("-o", "--output", dest="report", help="Write Results To File", metavar="FILE")
	parser.add_option("-i", "--imap", action='store_true', default=False, help="Use IMAP Server")
	parser.add_option("-w", "--pop", action='store_true', default=False, help="Use POP Server")
	group = OptionGroup(parser, "Web Server Options")
	group.add_option("-u", "--user", type="string", help="UserName")
	group.add_option("-p", "--passwd", type="string", help="Password")				  
	group.add_option("-f", "--folder", type="string", help="FolderName")
	parser.add_option_group(group)
	(options, args) = parser.parse_args()
	global tmpDir
	tmpDir = tempfile.mkdtemp()
	if len(args) != 2:
		parser.print_help()
	elif options.imap == True:
		emails = imapScan().parse(args[1], options.user, options.passwd, options.folder)
		for message in emails:
			attatch = attExtract().parse(message, options.extract)
			print "Scanning Attatchments"
			for att in attatch:
				results = yaraScan().scanner(att["msg"], args[0])
				if options.report and results:
					reportMain(options.report, att, results)

	elif options.pop == True:
		emails = popScan().parse(args[1], options.user, options.passwd)
		for message in emails:
			attatch = attExtract().parse(message, options.extract)
			for att in attatch:
				results = yaraScan().scanner(att["msg"], args[0])
				if options.report and results:
					reportMain(options.report, att, results)
	else:
		attatch = attExtract().parse(args[1], options.extract)
		print "Scanning Attatchments"
		for att in attatch:
			results = yaraScan().scanner(att["msg"], args[0])
			if options.report and results:
				reportMain(options.report, att, results)
	shutil.rmtree(tmpDir)

class attExtract:
	def parse(self, emailFile, extract):
		x = open(emailFile)
		msg = email.message_from_file(x)
		x.close()
		# Grab some references so we can identify the email later
		subjectLine = msg['subject']
		fromAdd = msg['from']
		# taken from the python docs tut
		counter = 1
		attatch = []
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
			# if declared extract all the files from the zip and write to tmp
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
						attatch.append ({"msg" : (os.path.join(tmpDir, filename)), "subject" : subjectLine, "from" : fromAdd})
			else:
				attatch.append ({"msg" : (os.path.join(tmpDir, filename)), "subject" : subjectLine, "from" : fromAdd})				
		return attatch	
	
class imapScan:
	def parse(self, server, user, pwd, folder):
		import imaplib
		print tmpDir		
		m = imaplib.IMAP4_SSL(server)
		m.login(user,pwd)
		m.select(folder)
		resp, items = m.search(None, "ALL") # IMAP Filter Rules here
		items = items[0].split()
		count = len(items)
		counter = 0
		emails = []
		print "Fetching %s Emails" % count
		for emailid in items:
			emailFile = os.path.join(tmpDir, folder+emailid + ".txt")
			counter +=1
			resp, data = m.fetch(emailid, "(RFC822)")
			email_body = data[0][1]
			msgFile = open(emailFile, "w")
			msgFile.write(email_body)
			msgFile.close()
			emails.append(emailFile)
		return emails

class popScan:
	def parse(self, server, user, pwd):
		import poplib
		m = poplib.POP3_SSL(server)
		m.user(user)
		m.pass_(pwd)
		emailCount, total_bytes = m.stat()
		counter = 0
		emails = []
		print "Fetching %s Emails" % emailCount
		for email in range(emailCount):
			counter +=1
			emailFile = os.path.join(tmpDir, server+str(counter) + ".txt")
			msgFile = open(emailFile, "w")
			for msg in m.retr(email+1)[1]:				
				msgFile.write(msg)
				msgFile.write("\n")
			msgFile.close()
			emails.append(emailFile)
		return emails

			
class yaraScan:
	def scanner(self, scanfile, yaraRule):
		yaraRules = yara.compile(yaraRule)
		matches = []
		if os.path.getsize(scanfile) > 0:
			for match in yaraRules.match(scanfile):
				matches.append({"name" : match.rule, "meta" : match.meta})
		return matches
		
class reportMain:
	def __init__(self, report, att, results):
		with open(report, "a") as f:
			f.write("----------\n")
			f.write("From: %s\n" % att["from"])
			f.write("Subject: %s\n" % att["subject"])
			f.write("Att Name: %s\n" % att["msg"])
			f.write("Matched Rules: \n")
			for m in results:
				f.write(m["name"] + "\n")
			f.write("----------\n")
			
if __name__ == "__main__":
	main()