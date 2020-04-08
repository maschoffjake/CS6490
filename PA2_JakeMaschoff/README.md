To run these files, make sure you have the following packages installed:
https://cryptography.io/en/latest/
https://pypi.org/project/pycrypto/

Then to run these files, use python3.
The structure of this code is bob.py (the server) and alice.py (the client), so you must start bob first by running:

python3 bob.py

Then you are able to run alice after bob has been started by running:

python3 alice.py

Alice will then begin the handshake between the 2 nodes. If anything goes wrong, an error message will print and the 
program will exit abrutly without a 'done print statement

The program Alice will request a file that it wants to download from the server. Currently it is set to 'frankenstein_book.txt' 
since that is the only file it can currently download

The output files for alice and bob are included to see all the exchanges that are taking place, but are also printed when the program is being run