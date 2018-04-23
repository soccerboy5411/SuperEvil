#!/usr/bin/python

import argparse
import re

parser = argparse.ArgumentParser(description='Cleans a string|regex from a specified log')
# argument for file path
parser.add_argument('-f', '--file', type=file, required=True,
                    help='Requires absolute path')
# creating a mutually exclusive group for requiring either a string or regex
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-s', '--string', nargs='+',
                   help='Provide a literal string to search for. Can accept more than one expression (del by space)')
group.add_argument('-r', '--regex', nargs='+',
                   help='Provide a regex to search for. Can accept more than one expression (del by space)')
# compiles the parser table into args
args = parser.parse_args()


# converts all searches to regex
if args.string:
    regex = re.escape(args.string)  # escapes special chars & compiles regex
else:
    regex = args.regex  # compiles regex

rm_count = 0  # creates the rm_count variable
clean_file = []  # creates a clean_log table

with open(args.file, 'r') as open_file:  # opens the file as read/write
    for line in open_file:
        match = re.search(regex, line)  # match == T/F
        if not match:  # if the regex wasn't found append the clean_file
            clean_file.append(line)
        else:  # else increment rm_count
            rm_count += 1
    for entry in clean_file:  # writes the clean_file table to the opened file
        open_file.write(entry+"\n")

print("Removed {0} items from {1}".format(rm_count, args.file))
