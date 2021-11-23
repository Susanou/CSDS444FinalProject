import argparse

# python caeser.py caesar -e plain.txt caesarkey.txt
# python caeser.py caesar -d plain.txt.enc caesarkey.txt
def caesar_encrypt(text,s):
    encry_result = ""
   # transverse the plain text
    for i in range(len(text)):
      encry = text[i]
      # Encrypt uppercase characters in plain text
      
      if (encry.isupper()):
         encry_result += chr((ord(encry) + s-65) % 26 + 65)
      # Encrypt lowercase characters in plain text
      elif (encry.isspace()):
          encry_result += " "
      else:
         encry_result += chr((ord(encry) + s - 97) % 26 + 97)
    print ("Encryption Result: " + encry_result)
    return encry_result
#check the above function
#text = "CEASER CIPHER DEMO"
#s = 4

#print ("Plain Text : " + text)
#print ("Shift pattern : " + str(s))
#print ("Cipher: " + caesar_encrypt(text,s))


def caesar_decrypt(text,s):
    decry_result = ""
   # transverse the plain text
    for i in range(len(text)):
      decry = text[i]
      # Encrypt uppercase characters in plain text
      
      if (decry.isupper()):
         decry_result += chr((ord(decry) - 65 + 26 - s) % 26 + 65)
      # Encrypt lowercase characters in plain text
      elif (decry.isspace()):
          decry_result += " "
      else:
         decry_result += chr((ord(decry) -97 + 26 - s) % 26 + 97)
    print ("Decryption Result: " + decry_result)
    return decry_result

#check the above function
#text = "GIEWIV GMTLIV HIQS"
#s = 4

#print ("Cipher text : " + text)
#print ("Shift pattern : " + str(s))
#print ("Plain text: " + caesar_decrypt(text,s))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="command line utility to encrypt and decrypt using different algorithms")

    subparsers = parser.add_subparsers(title="Cryptographic algoritgms",description="Algorithms supported", help="Additional help", dest="algo")
    
    # Create each algorithm's subparser
    ## AES PARSER
    parser_caesar = subparsers.add_parser("caesar", help="caesar help")
    group_caesar = parser_caesar.add_mutually_exclusive_group(required=True)
    group_caesar.add_argument("-e", "--encrypt", action="store_true")
    group_caesar.add_argument("-d", "--decrypt", action="store_true")
    parser_caesar.add_argument("filename", type=str, help="File containing the message to encrypt/decrypt")
    parser_caesar.add_argument("key", type=str, help="File containing the key used to encrypt/decrypt")
    parser_caesar.add_argument("-o", "--output", type=str, help="Output file", nargs='?')

    args = parser.parse_args()

    if args.algo == "caesar":
        if args.encrypt:
            with open(args.filename, "r") as f:
                plaintext = f.read()
            with open(args.key, "r") as f:
                key = int(f.read())
            if args.output != None:
                with open(args.output, "w") as f:
                    f.write(caesar_encrypt(plaintext, key))
            else:
                with open(args.filename+".enc", "w") as f:
                    f.write(caesar_encrypt(plaintext, key))
        elif args.decrypt:
            with open(args.filename, "r") as f:
                ciphertext = f.read()
            with open(args.key, "r") as f:
                key = int(f.read())

            if args.output != None:
                with open(args.output, "w") as f:
                    f.write(caesar_decrypt(ciphertext, key))
            else:
                with open(".".join(args.filename.split('.')[:2]), "w") as f:
                    f.write(caesar_decrypt(ciphertext, key))
        else:
            parser.print_help()
    else:
        parser.print_help()