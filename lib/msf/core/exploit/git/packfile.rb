module Msf

module Exploit::Git

  SIGNATURE = 'PACK'
  VERSION = 2

  ##
  # object types
  ##
  OBJ_COMMIT    = 1
  OBJ_TREE      = 2
  OBJ_BLOB      = 3
  OBJ_TAG       = 4
  # ?           = 5
  # type 5 is reserved
  # see: https://git-scm.com/docs/pack-format
  OBJ_OFS_DELTA = 6
  OBJ_REF_DELTA = 7

  class Packfile

    attr_reader :version, :git_objects, :data, :checksum

    def initialize(version = nil, objs)
      @version = version.nil? ? VERSION : version.to_i
      @git_objects = objs.kind_of?(Array) ? objs : [ objs ]

      pre_check_data = header + format_objects
      @checksum = Digest::SHA1.hexdigest(pre_check_data)
      @data = pre_check_data + [ @checksum ].pack('H*')
    end

    def header
      SIGNATURE + [ @version ].pack('N') + [ @git_objects.length ].pack('N')
    end

    # Each object has a variable-sized
    # header, with the size being determined
    # by the length of the object's original,
    # uncompressed content
    def format_objects
      type = 0
      obj_stream = []

      @git_objects.each do |obj|
        byte_amt = 1
        obj_data_size = obj.content.length
        case obj.type          
        when 'blob'
          type = OBJ_BLOB
        when 'tree'
          type = OBJ_TREE
        when 'commit'
          type = OBJ_COMMIT
        end
        
        num_bits = 0
        num = obj_data_size
        while num != 0
          num /= 2
          num_bits += 1
        end

        # the first byte can only hold
        # four bits of the size of the
        # object's content since the
        # leading bits are reserved for
        # value of MSB and object type
        if num_bits > 4
          if num_bits > 11
            byte_amt = num_bits / 7
            byte_amt += 1 if (num_bits % 7 > 0)
          else
            byte_amt = 2
          end
        end

        shift = 0
        (1..byte_amt).each do |byte|
          curr_byte = 0
          # set msb if needed
          if byte < byte_amt
            curr_byte |= 128
          end

          # set the object type
          # set last four bits for content size
          if byte == 1
            curr_byte |= (type << 4)
            curr_byte |= (obj_data_size & 15)
          else
            curr_byte = (obj_data_size >> 4 >> shift) & 127
            shift += 7
          end

          obj_stream << [ curr_byte ].pack('C*')
        end

        # Since the object type is denoted in the preceding
        # info, we only store the compressed object data
        obj_stream << Rex::Text.zlib_deflate(obj.content, Zlib::DEFAULT_COMPRESSION)
      end

      obj_stream = obj_stream.join
    end

    # Read the contents of the packfile and constructs
    # the objects found
    # @param [ String ] the packfile data
    # return Array of GitObjects found in the packfile
    def self.read_packfile(data)
      return nil unless data
      return nil if data.empty?

      pack_start = data.index('PACK')
      return nil unless pack_start

      data = data[pack_start..-1]
      version = data[4..7].unpack('N').first
      obj_count = data[8..11].unpack('N').first
      curr_pos = 12

      type = ''
      pack_objs = []
      (1..obj_count).each do |obj_index|
        # determine the current object's type first
        first_byte = data[curr_pos].unpack('C').first
        num_type = (first_byte & 0b01110000) >> 4
        case num_type
        when OBJ_COMMIT
          type = 'commit'
        when OBJ_TREE
          type = 'tree'
        when OBJ_BLOB
          type = 'blob'
        when OBJ_OFS_DELTA
          type = 'ofs-delta'
        when OBJ_REF_DELTA
          type = 'ref-delta'
        end

        # now determine the size of the object's uncompressed data
        shift = 4
        curr_byte = first_byte
        size = curr_byte & 0b00001111
        keep_reading = false
        if curr_byte >= 128
          keep_reading = true
        end

        curr_pos += 1
        while keep_reading
          curr_byte = data[curr_pos].unpack('C').first
          if curr_byte < 128
            keep_reading = false
          end

          size = (curr_byte << shift) | size
          shift += 7
          curr_pos += 1
        end

        # now decompress content and create Git object
        case type
        when 'ofs-delta'
          # get negative offset
          offset, curr_pos = get_variable_len_num(data, curr_pos)
          base_start = curr_pos - offset
          base_obj_sha = data[base_start..base_start+19].unpack('H*').first
        when 'ref-delta'
          base_obj_sha = data[curr_pos..curr_pos+19].unpack('H*').first
          curr_pos += 20
        end

        content = Rex::Text.zlib_inflate(data[curr_pos..-1])

        # delta objects are object types specific to packfile
        # and do not follow same format as other Git objects
        if type == 'ofs-delta' || type == 'ref-delta'
          delta_obj = read_delta(type, content, base_obj_sha)
          pack_objs << apply_delta(delta_obj, pack_objs)
        else
          sha1, compressed = GitObject.build_object(type, content)
          pack_objs << GitObject.new(type, content, sha1, compressed)
        end

        # update curr_pos to point to next obj header
        compressed_len = Rex::Text.zlib_deflate(content, Zlib::DEFAULT_COMPRESSION).length
        curr_pos = curr_pos + compressed_len
      end

      pack_objs
    end

    def self.read_delta(type, content, base_obj_sha)
      source_len = 0
      target_len = 0

      delta = { type: type, base: base_obj_sha }

      start = 0
      base_len, start = get_variable_len_num(content, start)
      target_len, start = get_variable_len_num(content, start)

      inst_type = ''
      inst = content[start].unpack('C').first
      start += 1
      num_bytes = 0
      if inst >= 128
        inst_type = 'copy'
        # now determine the offset
        shift = 0
        offset_mask = []
        off_bits = inst & 0b1111
        (0..3).each do |idx|
          if (off_bits >> idx) & 1 == 1
            num_bytes += 1
            offset_mask.prepend(0b11111111)
          else
            offset_mask.prepend(0b00000000)
          end
        end

        offset = 0
        unless num_bytes == 0
          shift = 0
          byte_idx = 0
          off_bytes = content[start].unpack("C#{num_bytes}")

          (0..3).each do |idx|
            if offset_mask[3 - idx] == 255
              offset |= ((off_bytes[byte_idx] & offset_mask[3 - idx]) << shift)
              byte_idx += 1
            else
              offset |= (0 << shift)
            end
            shift += 7
          end
        end

        delta[:offset] = offset
        size = 0
        num_bytes = 0
        size_mask = []
        size_bits = (inst & 0b01110000) >> 4
        start += num_bytes
        if size_bits == 0
          size = 0x10000
        else
          (0..2).each do |idx|
            if (size_bits >> idx) & 1 == 1
              num_bytes += 1
              size_mask.prepend(0b11111111)
            else
              size_mask.prepend(0b00000000)
            end
          end

          shift = 0
          byte_num = 0
          size_bytes = content[start].unpack("C#{num_bytes}")
          start += num_bytes
          (0..2).each do |idx|
            if size_mask[2 - idx] == 255
              size |= ((size_bytes[byte_num] & size_mask[2 - idx]) << shift)
              byte_num += 1
            else
              size |= (0 << shift)
            end
            shift += 7
          end
        end
      else
        inst_type = 'insert'
        size = inst & 0b0111111
        delta[:data] = content[start..start + size - 1]
      end
      delta[:size] = size
      delta[:inst] = inst_type

      delta
    end

    def self.apply_delta(delta, git_objects)
      target = nil

      case delta[:inst]
      when 'copy'
        base_obj = GitObject.find_object(delta[:base], git_objects)
        return nil unless base_obj

        offset = delta[:offset]
        size = delta[:size]
        type = base_obj.type

        content = base_obj.content
        content = content[offset..offset + size - 1]
        sha1, compressed = GitObject.build_object(type, content)
        target = GitObject.new(type, content, sha1, compressed)
      when 'insert'
        size = delta[:size]
        base_obj = GitObject.find_object(delta[:base], git_objects)
        type = base_obj.type
        sha1, compressed = GitObject.build_object(type, delta[:data])
        target = GitObject.new(type, delta[:data], sha1, compressed)
      end

      target
    end

    def self.get_variable_len_num(data, curr_pos)
      shift = 7
      curr_byte = data[curr_pos].unpack('C').first
      offset = curr_byte & 0b01111111
      curr_pos += 1

      while curr_byte >= 128
        curr_byte = data[curr_pos].unpack('C').first
        offset = (offset << shift) | (curr_byte & 0b01111111)
        shift += 7
        curr_pos += 1
      end
      new_pos = curr_pos
    
      return offset, new_pos
    end
  end
end
end
