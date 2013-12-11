# -*- coding: binary -*-

# Rex::Struct2
module Rex
module Struct2

# this is a "constant" element.  It's not actually constant, you can set it
# via the constructor and value.  It doesn't do from_s/to_s, etc.

# what use is it? Well it's useful for doing constant restraints (like fix
# sized arrays), and probably not a ton more.

class Constant

  require 'rex/struct2/element'
  include Rex::Struct2::Element

  def initialize(value)
    self.value = value
  end

end

# end Rex::Struct2
end
end
