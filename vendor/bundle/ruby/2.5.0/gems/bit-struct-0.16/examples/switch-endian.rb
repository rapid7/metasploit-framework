module ModuleMethodSaver
  def method_missing(meth, *args, &block)
    @saved ||= []
    @saved << [meth, args, block]
  end

  def included(m)
    if @saved
      @saved.each do |meth, args, block|
        m.send(meth, *args, &block)
      end
    end
  end
end


require 'bit-struct'

module MyFields
  extend ModuleMethodSaver

  unsigned  :x, 16
end

class LittleEndian < BitStruct
  default_options :endian => :little
  include MyFields
end

class BigEndian < BitStruct
  default_options :endian => :big
  include MyFields
end

le = LittleEndian.new
be = BigEndian.new

le.x = be.x = 256

p [le, le.to_s]
p [be, be.to_s]


__END__

Output:

[#<LittleEndian x=256>, "\000\001"]
[#<BigEndian x=256>, "\001\000"]
