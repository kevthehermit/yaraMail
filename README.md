yaraMail
========

Yara Scanner For IMAP Feeds and saved Streams

###What it does:
- reads an smtp formated email file or connects to IMAP / POP server
- reads emails and extracts attatchments. writes them to your os tmp dir
- If emails contains a zip file it extracts all the files and scans them
- Scans attatchemtns with chosen yara rule file.
- Writes the results to a Report File
- deletes the tmp dir created.

###Usage
- IMAP Feed
python yaraMail.py -e -o sampleReport.txt -i -u me@you.com -p password -f inbox sample.yar imap.gmail.com
- POP Feed
python yaraMail.py -e -o sampleReport.txt -w -u you@me.com -p password sample.yar pop3.live.com
- From File
python yaraMail.py -e -o sampleReport.txt sample.yar SampleMail.txt

###Reports

Here is an example of the report print out


From: Kevin Breen <email@email.com>  
Subject: Subject Line  
Att Name: Name of attatch.ext  
Matched Rules:  
Rule_Name1  
Rule_Name2  



###Misc
The Attachement extract also extracts any Body to the EMail in either text/plain or text/HTML format  
-The text body of the email is typically named as part-001.ksh (this is what python mime guesses the ext as)  
-The HTML Body of the text is typically named as part-002.html  

###ToDo

-Add verbose output




