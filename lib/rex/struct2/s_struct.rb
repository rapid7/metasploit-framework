# -*- coding: binary -*-

# Rex::Struct2
module Rex
module Struct2

class SStruct

  require 'rex/struct2/element'
  include Rex::Struct2::Element

  attr_reader  :leftover, :elements
  attr_writer  :leftover, :elements

  private :elements, :elements=

  # watch out!, leftover returns our copy of the string!  so don't do
  # anything stupid like struct.leftover.slice! !!

  def initialize(*opts)
    self.elements = [ ]
    self.add_element(*opts)
  end


  def reset
    elements.each {|e| e.reset}
    return self
  end

  def add_element(*objs)
    objs.each { |o|
      elements << o
      o.container = self
    }
    return self
  end

  def <<(obj)
    self.add_element(obj)
  end

  def to_s
    # !!! what do we do on mix restraint issues? just fail?
    # maybe throw an exception, because that is most likely
    # a usage error

    buff = ""
    elements.each do |e|
      buff << e.to_s
    end

    if restraint && restraint.max
      return buff.slice(0, restraint.max)
    else
      return buff
    end
  end

  def length
    return elements.length
  end

  def [](obj)
    return elements[obj]
  end

  def each(&block)
    return elements.each(&block)
  end

  def from_s(obytes)
    # make my own copy so I can chop it up
    bytes = obytes.dup
    length = 0

    # I don't think we should call update_restraint here, but
    # I could have mis thought or something

    # if we have a restraint (and if there is a val) truncate
    if restraint
      max = restraint.max
      bytes = bytes.slice(0, max) if max
    end

    elements.each { |e|
      used = e.from_s(bytes)
      return if !used
      bytes.slice!(0, used)
      length += used
    }

    # make sure we matched out min restraint, else return failure
    if restraint
      min = restraint.min
      return if min && length < min
    end

    # I guess this is me getting "set", so I should have a value
    # and I should update my restraints on set
    self.value = obytes.slice(0, length)

    self.leftover = bytes
    return(length)
  end

end

# end Rex::Struct2
end
end
