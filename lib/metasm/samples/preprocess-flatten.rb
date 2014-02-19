#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this file takes preprocessor files as arguments
# it preprocesses their content and dump the result to stdout
# it also dumps all macro definitions
#

require 'metasm/preprocessor'

p = Metasm::Preprocessor.new
p.feed(ARGF.read)
raw = p.dump
puts p.dump_macros(p.definition.keys, false)
puts raw
