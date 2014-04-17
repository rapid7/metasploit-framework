#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

class Metasm::MIPS < Metasm::CPU
end

require 'metasm/main'
require 'metasm/cpu/mips/parse'
require 'metasm/cpu/mips/encode'
require 'metasm/cpu/mips/decode'
require 'metasm/cpu/mips/render'
require 'metasm/cpu/mips/debug'
