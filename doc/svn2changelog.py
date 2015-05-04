#!/usr/bin/python

import sys
from xml.etree.ElementTree import iterparse #, dump # to dump xml nodes

#firstarg = sys.argv[1]

blacklist = ["cosmetic", "refresh", "inor change", "inor fix", "comments"]

iparse = iterparse(sys.stdin, ['start', 'end'])

for event, elem in iparse:
	if event == 'start' and elem.tag == 'log':
		logNode = elem
		break

logentries = (elem for event, elem in iparse if event == 'end' and elem.tag == 'logentry')

for logentry in logentries:
	skip = 0
	for word in blacklist:
		if word in logentry.find('msg').text:
			skip = 1
			break
	
	if not skip:
		#dump(logentry) # to dump xml node
		paths = logentry.find('paths')
		print "Files:"
		for path in paths.findall('path'):
			print path.text[7:]
		print "Comment:"
		print logentry.find('msg').text
	
	logNode.remove(logentry)

