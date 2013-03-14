##
# We manage a set of attributes. Each attribute has a symbol name and a bit
# value.

class RDoc::Markup::Attribute

  ##
  # Special attribute type.  See RDoc::Markup#add_special

  SPECIAL = 1

  @@name_to_bitmap = { :_SPECIAL_ => SPECIAL }
  @@next_bitmap = 2

  ##
  # Returns a unique bit for +name+

  def self.bitmap_for(name)
    bitmap = @@name_to_bitmap[name]
    unless bitmap then
      bitmap = @@next_bitmap
      @@next_bitmap <<= 1
      @@name_to_bitmap[name] = bitmap
    end
    bitmap
  end

  ##
  # Returns a string representation of +bitmap+

  def self.as_string(bitmap)
    return "none" if bitmap.zero?
    res = []
    @@name_to_bitmap.each do |name, bit|
      res << name if (bitmap & bit) != 0
    end
    res.join(",")
  end

  ##
  # yields each attribute name in +bitmap+

  def self.each_name_of(bitmap)
    @@name_to_bitmap.each do |name, bit|
      next if bit == SPECIAL
      yield name.to_s if (bitmap & bit) != 0
    end
  end

end

