#!/usr/bin/env python3

import lief
import sys

p = lief.parse(sys.argv[1])
loader = bytes(p.get_section('__text').content)
open(sys.argv[2], 'wb').write(loader)
