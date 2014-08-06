#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# fix autorequire warning
class Metasm::Ia32 < Metasm::CPU
end

require 'metasm/main'
require 'metasm/cpu/ia32/parse'
require 'metasm/cpu/ia32/encode'
require 'metasm/cpu/ia32/decode'
require 'metasm/cpu/ia32/render'
require 'metasm/cpu/ia32/compile_c'
require 'metasm/cpu/ia32/decompile'
require 'metasm/cpu/ia32/debug'
