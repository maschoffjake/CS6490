For the architecture used in this assigment, Alice is represented using the number 1, Bob is number 2, and the KDC is number 3.
KDC is listening on port 5000, where Bob is listening on port 5001
There are 2 different directories with files:
    Needham_Schroeder_Reflection_Attack
    Expanded_Needham_Schroeder

The first contains the implemnetation of the reflection attack implementation.
The second contains the expanded Needham Schroeder implementation that doesn't allow for reflection attacks.

For the expanded Needham Schroeder implementation I used a JSON protocol for sending messages. 
For the normal Needham Schroder implementation I used JSON for the first 2 messages, then just concatenated the bytes for the final 3 messages. I needed
to change this implementation in order to perform the reflection attack with Trudy.

Used the library pycrypto (https://pypi.org/project/pycrypto/) to help with the 3DES implementation.

In order to run this architecture, you must run Bob and KDC before running Alice/Trudy.

To run each of these programs, you need to use python3.
Each of these files also have an optional '--ecb' flag that you can set. When setting this flag, the program will use 3DES with
ECB ciphers. If not, the files will use 3DES with CBC ciphers. When running these files, make sure that they share the same cipher methods (i.e ECB vs. CBC)
otherwise there will be unexpected results.

Example of running architecture with CBC:
python3 bob.py
python3 KDC.py
python3 alice.py

Example of running architecture with ECB:
python3 bob.py --ecb
python3 KDC.py --ecb
python3 alice.py --ecb