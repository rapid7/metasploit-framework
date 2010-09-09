#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this file loads all metasm files and removes the autorequire feature
# on const_missing

require 'metasm'

class Module
	alias const_missing premetasm_const_missing
end

module Metasm
	Const_autorequire.values.flatten.each { |f| require 'metasm/'+f }
end
