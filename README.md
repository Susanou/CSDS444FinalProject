# CSDS444FinalProject
Repo to host our final crypto project for CSDS444 Computer Security class @ CWRU

Command to run Caesar:
Encryption: python tool.py caesar -e plain.txt caesarkey.txt
Decryption: python tool.py caesar -d plain.txt.enc caesarkey.txt
Command to run Vigenere:
Encryption: python tool.py vigenere -e vigenereplain.txt vigenerekey.txt
Decryption: python tool.py vigenere -d vigenereplain.txt.enc vigenerekey.txt

Command for AES
enc: `python3 tool.py aes -e plain.txt key.txt -o plain.enc`
dec: `python3 toll.py aes -d plain.enc key.txt -o dec_plain.txt`