import argparse
import os
import json
import sys
import pathlib

from aes import decrypt, encrypt

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




    # Parsing aguments
    args = parser.parse_args()

    if args.algo == "aes":
        print(args)
    else:
        parser.print_help()