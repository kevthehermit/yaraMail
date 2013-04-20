yaraMail
========

Yara Scanner For IMAP Feeds and saved Streams

###What it does:
- reads an smtp formated email file or connects to imap server
- reads emails and extracts attatchments. writes them to your os tmp dir
- Scans attatchemtns with chosen yara rule file.
- If emails contains a zip file it extracts all the files and scans them
- deletes the tmp dir created.

###Usage:

python yaraMail.py
Usage: yaraMail.py [options] smtpFile | imap Folder Name
Yara Mail Scanner, use it to Scan Email Attatchments

Options:
--version
		show program's version number and exit
-h, --help
		show this help message and exit
-r FILE, --Rules=FILE
		Yara Rule File
-e, --extract
		Extract Files if Zip Archive detected Deafult is No
IMAP OPTIONS:
-u USER, --user=USER
		IMAP UserName
-p PASSWD, --passwd=PASSWD
		IMAP Password
-s SERVER, --server=SERVER
		IMAP ServerName

###What it will do:

- Accept POP Accounts.
- Nicer Output to screen.
- Write a report file. 


