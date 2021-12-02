# CSDS444FinalProject
Repo to host our final crypto project for CSDS444 Computer Security class @ CWRU

Command to run Caesar:
Encryption: python tool.py caesar -e plain.txt caesarkey.txt
Decryption: python tool.py caesar -d plain.txt.enc caesarkey.txt

Command to run Vigenere:
Encryption: python tool.py vigenere -e vigenereplain.txt vigenerekey.txt
Decryption: python tool.py vigenere -d vigenereplain.txt.enc vigenerekey.txt

Command for AES:
enc: `python3 tool.py aes -e plain.txt key.txt -o plain.enc`
dec: `python3 tool.py aes -d plain.enc key.txt -o dec_plain.txt`

Command for Circular Bit Shift:
choose block size B and shift amount N
enc: `python3 tool.py circularBitShift -e plain.txt B N -o ciphertext.enc`
dec: `python3 tool.py circularBitShift -d ciphertext.enc B N -o dec_plain.txt`

Command for Base64:
enc: `python3 tool.py base64_tool -e plain.txt -o ciphertext.enc`
dec: `python3 tool.py base64_tool -d ciphertext.enc -o dec_plain.txt`
