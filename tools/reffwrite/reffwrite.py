#!/usr/bin/env python3

import sys
import argparse

def readdb(path):
	db = dict()

	f = open(path)
	for line in f:
		l = line.strip().split()
		db[l[0]] = l[1]

	return db

def rewrite(src, dst, db, colnum):
	for line in src:
		if not line[0].isdigit():
			dst.write(line)
			continue

		d = line.strip().split(",")
		val = d[colnum]
		if val in db:
			d[colnum] = db[val]

		dst.write(",".join(d) + "\n")

def main():
	parser = argparse.ArgumentParser(description='Rewrite column values in ARFF files')
	parser.add_argument('colnum', type=int, help='column number')
	parser.add_argument('dictionary', type=str, help='file with source->destination mappings')
	args = parser.parse_args()

	db = readdb(args.dictionary)
	rewrite(sys.stdin, sys.stdout, db, args.colnum - 1)

if __name__ == "__main__":
	main()
