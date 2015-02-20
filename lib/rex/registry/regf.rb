# -*- coding: binary -*-
module Rex
module Registry

class RegfBlock

  attr_accessor :timestamp, :root_key_offset

  def initialize(hive)

    regf_header = hive[0x00, 4]

    if regf_header !~ /regf/
      puts "Not a registry hive"
      return
    end

    @timestamp = hive[0x0C, 8].unpack('q').first
    @root_key_offset = 0x20

  end
end

end
end
