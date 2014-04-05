# -*- coding: binary -*-
require_relative "lfkey"
require_relative "valuelist"

module Rex
module Registry

class NodeKey

  attr_accessor :timestamp, :parent_offset, :subkeys_count, :lf_record_offset
  attr_accessor :value_count, :value_list_offset, :security_key_offset
  attr_accessor :class_name_offset, :name_length, :class_name_length, :full_path
  attr_accessor :name, :lf_record, :value_list, :class_name_data, :readable_timestamp

  def initialize(hive, offset)

    offset = offset + 0x04

    nk_header = hive[offset, 2]
    nk_type = hive[offset+0x02, 2]

    if nk_header !~ /nk/
      return
    end

    @timestamp = hive[offset+0x04, 8].unpack('q').first
    @parent_offset = hive[offset+0x10, 4].unpack('l').first
    @subkeys_count = hive[offset+0x14, 4].unpack('l').first
    @lf_record_offset = hive[offset+0x1c, 4].unpack('l').first
    @value_count = hive[offset+0x24, 4].unpack('l').first
    @value_list_offset = hive[offset+0x28, 4].unpack('l').first
    @security_key_offset = hive[offset+0x2c, 4].unpack('l').first
    @class_name_offset = hive[offset+0x30, 4].unpack('l').first
    @name_length = hive[offset+0x48, 2].unpack('c').first
    @class_name_length = hive[offset+0x4a, 2].unpack('c').first
    @name = hive[offset+0x4c, @name_length].to_s

    windows_time = @timestamp
    unix_time = windows_time/10000000-11644473600
    ruby_time = Time.at(unix_time)

    @readable_timestamp = ruby_time

    @lf_record = LFBlock.new(hive, @lf_record_offset + 0x1000) if @lf_record_offset != -1
    @value_list = ValueList.new(hive, @value_list_offset + 0x1000, @value_count) if @value_list_offset != -1

    @class_name_data = hive[@class_name_offset + 0x04 + 0x1000, @class_name_length]

  end

end

end
end
