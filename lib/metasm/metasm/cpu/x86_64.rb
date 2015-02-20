#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

class Metasm::X86_64 < Metasm::Ia32
end

require 'metasm/main'
require 'metasm/cpu/x86_64/parse'
require 'metasm/cpu/x86_64/encode'
require 'metasm/cpu/x86_64/decode'
require 'metasm/cpu/x86_64/render'
require 'metasm/cpu/x86_64/debug'
require 'metasm/cpu/x86_64/compile_c'
