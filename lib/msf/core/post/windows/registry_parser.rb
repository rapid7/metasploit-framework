module Msf
class Post
module Windows

  class RegistryParser
    # Constants
    ROOT_KEY        = 0x2c
    REG_NONE        = 0x00
    REG_SZ          = 0x01
    REG_EXPAND_SZ   = 0x02
    REG_BINARY      = 0x03
    REG_DWORD       = 0x04
    REG_MULTISZ     = 0x07
    REG_QWORD       = 0x0b


    # Magic strings

    # REGF magic value: 'regf'
    REGF_MAGIC = 0x72656766
    # NK magic value: 'nk'
    NK_MAGIC = 0x6E6B
    # VK magic value: 'vk'
    VK_MAGIC = 0x766B
    # LF magic value: 'lf'
    LF_MAGIC = 0X6C66
    # LH magic value: 'lh'
    LH_MAGIC = 0X6C68
    # RI magic value: 'ri'
    RI_MAGIC = 0X7269
    # SK magic value: 'sk'
    SK_MAGIC = 0X7269
    # HBIN magic value: 'hbin'
    HBIN_MAGIC = 0x6862696E

    class RegRegf < BinData::Record
      endian :little

      bit32  :magic, initial_value: REGF_MAGIC
      uint32 :sequence1
      uint32 :sequence2
      uint64 :last_change
      uint32 :major_version
      uint32 :minor_version
      uint32 :unknown1
      uint32 :unknown2
      uint32 :offset_first_record
      uint32 :data_size
      uint32 :unknown3
      string :name, length: 48
      string :remaining1, length: 411
      uint32 :checksum, initial_value: 0xFFFFFFFF
      string :remaining2, length: 3585
    end

    class RegNk < BinData::Record
      endian :little

      bit16  :magic, initial_value: NK_MAGIC
      uint16 :nk_type
      uint64 :last_change
      uint32 :unknown
      int32  :offset_parent
      uint32 :num_sub_keys
      uint32 :unknown2
      int32  :offset_sub_key_lf
      uint32 :unknown3
      uint32 :num_values
      int32  :offset_value_list
      int32  :offset_sk_rRecord
      int32  :offset_class_name
      string :unused, length: 20
      uint16 :name_length, initial_value: -> { self.key_name.length }
      uint16 :class_name_length
      string :key_name, read_length: -> { self.name_length }
    end

    class RegVk < BinData::Record
      endian :little

      bit16  :magic, initial_value: VK_MAGIC
      uint16 :name_length, initial_value: -> { self.name.length }
      int32  :data_len
      uint32 :offset_data
      uint32 :value_type
      uint16 :flag
      uint16 :unused
      string :name, read_length: -> { self.name_length }
    end

    class RegHash < BinData::Record
      endian :little

      int32  :offset_nk
      string :key_name, length: 4
    end

    class RegHash2 < BinData::Record
      endian :little

      int32  :offset_nk
    end

    class RegLf < BinData::Record
      endian :little

      bit16  :magic, initial_value: LF_MAGIC
      uint16 :num_keys
      array  :hash_records, type: :reg_hash, read_until: -> { index == (self.num_keys - 1) }
    end

    class RegLh < BinData::Record
      endian :little

      bit16  :magic, initial_value: LH_MAGIC
      uint16 :num_keys
      array  :hash_records, type: :reg_hash, read_until: -> { index == (self.num_keys - 1) }
    end

    class RegRi < BinData::Record
      endian :little

      bit16  :magic, initial_value: RI_MAGIC
      uint16 :num_keys
      array  :hash_records, type: :reg_hash2, read_until: -> { index == (self.num_keys - 1) }
    end

    class RegSk < BinData::Record
      endian :little

      bit16  :magic, initial_value: SK_MAGIC
      uint16 :unused
      int32  :offset_previous_sk
      int32  :offset_next_sk
      uint32 :usage_counter
      uint32 :size_sk, initial_length: -> { self.data.do_num_bytes }
      string :data, read_length: -> { self.size_sk }
    end

    class RegHbinBlock < BinData::Record
      attr_reader :record_type

      endian :little

      int32  :data_block_size#, byte_align: 4
      choice :data, selection: -> { @obj.parent.record_type } do
        reg_nk 'nk'
        reg_vk 'vk'
        reg_lf 'lf'
        reg_lh 'lh'
        reg_ri 'ri'
        reg_sk 'sk'
        string :default, read_length: -> { self.data_block_size == 0 ? 0 : self.data_block_size.abs - 4 }
      end
      string :unknown, length: -> { self.data_block_size.abs - self.data.do_num_bytes - 4 }

      def do_read(io)
        io.with_readahead do
          io.seekbytes(4)
          @record_type = io.readbytes(2)
        end
        #pad = (4 - (io.offset % 4)) % 4
        #io.seekbytes(pad)
        super(io)
      end
    end

    class RegHbin < BinData::Record
      endian :little

      bit32  :magic, initial_value: HBIN_MAGIC
      uint32 :offset_first_hbin
      uint32 :hbin_size
      string :unknown, length: 16
      uint32 :offset_next_hbin #hbin_size
      array  :reg_hbin_blocks, type: :reg_hbin_block, read_until: :eof
    end

    def initialize(hive_data)
      @hive_data = hive_data.b
      @regf = RegRegf.read(hive_data)
      @root_key = find_root_key
    end

    def find_root_key
      reg_hbin = nil
      # Split the data in 4096-bytes blocks
      @hive_data.unpack('a4096' * (@hive_data.size / 4096)).each do |data|
        next unless data[0,4] == 'hbin'
        reg_hbin = RegHbin.read(data)
        root_key = reg_hbin.reg_hbin_blocks.find do |block|
          block.data.respond_to?(:magic) && block.data.magic == NK_MAGIC &&block.data.nk_type == ROOT_KEY
        end
        return root_key if root_key
      rescue IOError
        raise StandardError, 'Cannot parse the RegHbin structure'
      end
      raise StandardError, 'Cannot find the RootKey' unless reg_hbin
    end

    def get_value(reg_key, reg_value)
      reg_key = find_key(reg_key)
      return nil unless reg_key

      if reg_key.data.num_values > 0
        value_list = get_value_blocks(reg_key.data.offset_value_list, reg_key.data.num_values + 1)
        value_list.each do |value|
          if value.data.name == reg_value
            return value.data.value_type, get_value_data(value)
          elsif reg_value == 'default' && value.data.flag <= 0
            return value.data.value_type, get_value_data(value)
          end
        end
      end
      nil
    end

    def find_key(key)
      # Let's strip '\' from the beginning, except for the case of
      # only asking for the root node
      key = key[1..-1] if key[0] == '\\' && key.size > 1

      parent_key = @root_key
      if key.size > 0 && key[0] != '\\'
        key.split('\\').each do |sub_key|
          res = find_sub_key(parent_key, sub_key)
          return nil unless res
          parent_key = res
        end
      end
      parent_key
    end

    def find_sub_key(parent_key, sub_key)
      block = get_block(parent_key.data.offset_sub_key_lf)
      # Let's search the hash records for the name
      if block.data.magic == RI_MAGIC
        block.data.hash_records.each do |hash_record|
          l = get_block(hash_record.offset_nk)
          # TODO

        end
      end
      #parent_key.data.num_sub_keys
      block.data.hash_records.each do |hash_record|
        res = compare_hash(block.data.magic, hash_record, sub_key)
        if res
          nk = get_block(res)
          return nk if nk.data.key_name == sub_key
        end
      end
    end

    def get_block(offset)
      block = RegHbinBlock.read(@hive_data[4096+offset..-1])
    end

    def compare_hash(magic, hash_rec, key)
      case magic
      when LF_MAGIC
        if hash_rec.key_name.gsub(/(^\x00*)|(\x00*$)/, '') == key[0,4]
          return hash_rec.offset_nk
        end
      when LH_MAGIC
        if hash_rec.key_name.unpack('<L').first == get_lh_hash(key)
          return hash_rec.offset_nk
        end
      when RI_MAGIC
        offset = hash_rec.offset_nk
        nk = get_block(offset)
        return offset if nk.key_name == key
      else
        raise StandardError, "Unknow magic: #{magic}"
      end
    end

    def get_lh_hash(key)
      res = 0
      key.upcase.bytes do |byte|
        res *= 37
        res += byte.ord
      end
      return res % 0x100000000
    end

    def get_value_blocks(offset, count)
      value_list = []
      res = []
      count.times do |i|
        value_list << @hive_data[4096+offset+i*4, 4].unpack('<l').first
      end
      value_list.each do |value_offset|
        if value_offset > 0
          block = get_block(value_offset)
          res << block
        end
      end
      return res
    end

    def get_value_data(record)
      # We should receive a VK record
      return '' if record.data.data_len == 0
      # if DataLen < 5 the value itself is stored in the Offset field
      return record.data.offset_data.to_binary_s if record.data.data_len < 0
      return self.get_data(record.data.offset_data, record.data.data_len + 4)
    end

    def get_data(offset, count)
      @hive_data[4096+offset, count][4..-1]
    end

    def enum_key(parent_key)
      res = []
      # If we're here.. we have a valid NK record for the key
      # Now let's searcht the subkeys
      if parent_key.data.num_sub_keys > 0
        lf = get_block(parent_key.data.offset_sub_key_lf)
        data = lf.data.hash_records

        if lf.data.magic == RI_MAGIC
          # ri points to lf/lh records, so we must parse them before
          records = ''
          # TODO
          #for i in range(lf['NumKeys']):
          #    offset = unpack('<L', data[:4])[0]
          #    l = self.__getBlock(offset)
          #    records = records + l['HashRecords'][:l['NumKeys']*8]
          #    data = data[4:]
          #data = records
        end

        data.each do |reg_hash|
          nk = get_block(reg_hash.offset_nk)
          res << nk.data.key_name.to_s.b
        end
      end

      return res
    end

    def enum_values(key)
      res = []
      value_list = get_value_blocks(key.data.offset_value_list, key.data.num_values + 1)
      value_list.each do |value|
        if value.data.flag > 0
          res << value.data.name
        else
          res << 'default'.b
        end
      end
      res
    end


  end



end
end
end
