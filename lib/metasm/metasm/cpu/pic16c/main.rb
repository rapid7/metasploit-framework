#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class Pic16c < CPU
  def initialize(endianness = :big)
    super()
    @endianness = endianness
    init
  end
end
end
