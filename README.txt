The tool is very basic right now. it takes logs via stdin and outputs 
instructions from machines compromised by brodos, itoknoproblembro, and 
that is good varients. If you would like to help the community out 
and send us your parsed logs of infected machines that would be awesome
you can send the txt files to plxsert@prolexic.com. The banner and exit
statement are sent to stderr so they will not be pipes to a file or logs 
for ease of use. This saves a grep -v instruction =).

Standard usage with example file
Usage: cat access.log | python brolog.py # please not to hit ctrl+c when done.

Output to screen with log
Usage: cat access.log | python brolog.py | tee bro.log
