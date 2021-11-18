import argparse
import os
import json
import sys
import pathlib

from aes import decrypt, encrypt

def padding(data):
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return data

def unpad(data):
    return data[:-data[-1]]



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="command line utility to encrypt and decrypt using different algorithms")

    subparsers = parser.add_subparsers(title="Cryptographic algoritgms",description="Algorithms supported", help="Additional help", dest="algo")
    
    # Create each algorithm's subparser
    ## AES PARSER
    parser_aes = subparsers.add_parser("aes", help="AES help")
    group_aes = parser_aes.add_mutually_exclusive_group(required=True)
    group_aes.add_argument("-e", "--encrypt", action="store_true")
    group_aes.add_argument("-d", "--decrypt", action="store_true")
    parser_aes.add_argument("filename", type=str, help="File containing the message to encrypt/decrypt")
    parser_aes.add_argument("key", type=str, help="File containing the key used to encrypt/decrypt")
    parser_aes.add_argument("-o", "--output", type=str, help="Output file", nargs='?')

    ## RSA PARSER
    parser_rsa = subparsers.add_parser("rsa", help="RSA help")
    group_rsa = parser_rsa.add_mutually_exclusive_group(required=True)
    group_rsa.add_argument("-e", "--encrypt", action="store_true")
    group_rsa.add_argument("-d", "--decrypt", action="store_true")
    group_rsa.add_argument("-c", "--create", action="store_true")
    parser_rsa.add_argument("filename", type=str, help="File containing the message to encrypt/decrypt")
    parser_rsa.add_argument("key", type=str, help="File containing the key used to encrypt/decrypt")




    # Parsing aguments
    args = parser.parse_args()

    if args.algo == "aes":
        if args.encrypt:
            with open(args.filename, "rb") as f:
                plaintext = padding(f.read())
            with open(args.key, "rb") as f:
                key = padding(f.read())

            if args.output != None:
                with open(args.output, "wb") as f:
                    f.write(encrypt(key, plaintext))
            else:
                with open(args.filename+".enc", "wb") as f:
                    f.write(encrypt(key, plaintext))
        else:
            with open(args.filename, "rb") as f:
                ciphertext = f.read()
            with open(args.key, "rb") as f:
                key = padding(f.read())

            if args.output != None:
                with open(args.output, "wb") as f:
                    f.write(decrypt(key, ciphertext))
            else:
                with open(args.filename+".dec", "wb") as f:
                    f.write(unpad(decrypt(key, ciphertext)))
    else:
        parser.print_help()