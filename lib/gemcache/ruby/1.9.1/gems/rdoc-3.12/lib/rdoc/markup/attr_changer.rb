class RDoc::Markup

  AttrChanger = Struct.new :turn_on, :turn_off # :nodoc:

end

##
# An AttrChanger records a change in attributes. It contains a bitmap of the
# attributes to turn on, and a bitmap of those to turn off.

class RDoc::Markup::AttrChanger

  def to_s # :nodoc:
    "Attr: +#{RDoc::Markup::Attribute.as_string turn_on}/-#{RDoc::Markup::Attribute.as_string turn_off}"
  end

  def inspect # :nodoc:
    "+%s/-%s" % [
      RDoc::Markup::Attribute.as_string(turn_on),
      RDoc::Markup::Attribute.as_string(turn_off),
    ]
  end

end

