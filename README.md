firehose53
===========
A tool to very quickly send a set of records to a list of DNS servers.

Usage:

 firehose53 -f records.txt 8.8.8.8

 firehose53 -t=32 -j=4 -r "A google.com.,MX google.com." 8.8.8.8 8.8.4.4

This uses 32 threads, and 4 processors to send these records to these IP's.

Results are output as JSON
