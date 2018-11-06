# Example to show how to programmatically "cut and paste" some of the fields
# from one BitStruct class into another.

require 'bit-struct'

class BS1 < BitStruct
  unsigned      :f1,     8
  unsigned      :f2,     8
  unsigned      :f3,     8
  unsigned      :f4,     8
  unsigned      :f5,     8
end

class BS2 < BitStruct
  fields_to_add = BS1.fields.select {|f| f.name.to_s =~ /[234]/}

  fields_to_add.each do |field|
    add_field(field.name, field.length, field.options)
  end
end

puts BS2.describe
