#!/usr/bin/env python3

import os, sys

os.chdir(sys.argv[1])

def recursive(path):
	base = path
	for path in os.listdir(path):
		abspath = os.path.join(base, path).replace('\\', '/')
		sys.stderr.write('Packing ' + abspath+'\n')
		if os.path.isdir(abspath):
			print("mkdir(\"%s\", 0777);" % abspath)
			recursive(abspath)
		else:
			print("{")
			print("  unsigned char content[] = {%s};" % ((', '.join('%d' % x for x in open(abspath, "rb").read()))))
			print("  write_file(\"%s\", content, sizeof(content));" % abspath)
			print("}")

recursive('.')