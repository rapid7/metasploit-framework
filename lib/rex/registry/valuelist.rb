# -*- coding: binary -*-
require_relative "valuekey"

module Rex
module Registry

class ValueList

  attr_accessor :values

  def initialize(hive, offset, number_of_values)
    offset = offset + 4
    inner_offset = 0

    @values = []

    1.upto(number_of_values) do |v|
      valuekey_offset = hive[offset + inner_offset, 4]
      next if !valuekey_offset

      valuekey_offset = valuekey_offset.unpack('l').first
      @values << ValueKey.new(hive, valuekey_offset + 0x1000)
      inner_offset = inner_offset + 4
    end
  end
end

end
end
