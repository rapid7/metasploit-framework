# -*- coding: binary -*-
module Rex
module Registry

class ValueKey

  attr_accessor :name_length, :length_of_data, :data_offset, :full_path
  attr_accessor :value_type, :readable_value_type, :name, :value

  def initialize(hive, offset)
    offset = offset + 4

    vk_header = hive[offset, 2]

    if vk_header !~ /vk/
      puts "no vk at offset #{offset}"
      return
    end

    @name_length = hive[offset+0x02, 2].unpack('c').first
    @length_of_data = hive[offset+0x04, 4].unpack('l').first
    @data_offset = hive[offset+ 0x08, 4].unpack('l').first
    @value_type = hive[offset+0x0C, 4].unpack('c').first

    if @value_type == 1
      @readable_value_type = "Unicode character string"
    elsif @value_type == 2
      @readable_value_type = "Unicode string with %VAR% expanding"
    elsif @value_type == 3
      @readable_value_type = "Raw binary value"
    elsif @value_type == 4
      @readable_value_type = "Dword"
    elsif @value_type == 7
      @readable_value_type = "Multiple unicode strings separated with '\\x00'"
    end

    flag = hive[offset+0x10, 2].unpack('c').first

    if flag == 0
      @name = "Default"
    else
      @name = hive[offset+0x14, @name_length].to_s
    end

    @value = ValueKeyData.new(hive, @data_offset, @length_of_data, @value_type, offset)
  end
end

class ValueKeyData

  attr_accessor :data

  def initialize(hive, offset, length, datatype, parent_offset)
    offset = offset + 4

    #If the data-size is lower than 5, the data-offset value is used to store
    #the data itself!
    if length < 5
      @data = hive[parent_offset + 0x08, 4]
    else
      @data = hive[offset + 0x1000, length]
    end
  end
end

end
end
