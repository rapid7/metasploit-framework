# -*- coding: binary -*-
require_relative "nodekey"

module Rex
module Registry

class LFBlock

  attr_accessor :number_of_keys, :hash_records, :children

  def initialize(hive_blob, offset)
    offset = offset + 4
    lf_header = hive_blob[offset, 2]

    if lf_header !~ /lf/ && lf_header !~ /lh/
      return
    end

    @number_of_keys = hive_blob[offset + 0x02, 2].unpack('C').first

    @hash_records = []
    @children = []

    hash_offset = offset + 0x04

    1.upto(@number_of_keys) do |h|

      hash = LFHashRecord.new(hive_blob, hash_offset)

      @hash_records << hash

      hash_offset = hash_offset + 0x08

      @children << NodeKey.new(hive_blob, hash.nodekey_offset + 0x1000)
    end
  end
end

class LFHashRecord

  attr_accessor :nodekey_offset, :nodekey_name_verification

  def initialize(hive_blob, offset)
    @nodekey_offset = hive_blob[offset, 4].unpack('l').first
    @nodekey_name_verification = hive_blob[offset+0x04, 4].to_s
  end

end

end
end
