#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

class Metasm::ARM64 < Metasm::CPU
end
Metasm::AArch64 = Metasm::ARM64

require 'metasm/main'
require 'metasm/cpu/arm64/parse'
require 'metasm/cpu/arm64/encode'
require 'metasm/cpu/arm64/decode'
require 'metasm/cpu/arm64/render'
require 'metasm/cpu/arm64/debug'
