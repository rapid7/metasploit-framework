require 'rex/text'

module Rex::Proto::MsTds
  # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac
  class MsTdsLogin7 < BinData::Record
    endian :little

    class << self
      private

      @@buffer_fields = []
      @@buffer_field_types = {}

      def buffer_field(field_name, encoding:, onlyif: true, field_type: nil)
        @@buffer_fields << field_name

        uint16 "ib_#{field_name}".to_sym, initial_value: -> { buffer_field_offset(field_name) || 0 }, onlyif: onlyif
        case encoding
        when Encoding::ASCII_8BIT
          @@buffer_field_types[field_name] = (field_type || :uint8_array)
          uint16 "cb_#{field_name}".to_sym, initial_value: -> { send(field_name)&.length || 0 }, onlyif: onlyif
        when Encoding::UTF_16LE
          @@buffer_field_types[field_name] = (field_type || :string16)
          uint16 "cch_#{field_name}".to_sym, initial_value: -> { send(field_name)&.length || 0 }, onlyif: onlyif
        else
          raise RuntimeError, "Unsupported encoding: #{encoding}"
        end
      end
    end

    uint32  :packet_length, initial_value: :num_bytes
    ms_tds_version  :tds_version, initial_value: MsTdsVersion::VERSION_7_1
    uint32  :packet_size
    uint32  :client_prog_ver, initial_value: 0x07
    uint32  :client_pid, initial_value: -> { rand(1024+1) }
    uint32  :connection_id

    struct  :option_flags_1 do
      bit1  :f_set_lang, initial_value: 1
      bit1  :f_database
      bit1  :f_use_db, initial_value: 1
      bit1  :f_dump_load
      bit2  :f_float
      bit1  :f_char
      bit1  :f_byte_order
    end

    struct  :option_flags_2 do
      bit1  :f_int_security
      bit3  :f_user_type
      bit1  :f_tran_boundary
      bit1  :f_cache_connect
      bit1  :f_odbc, initial_value: 1
      bit1  :f_language
    end

    struct  :type_flags do
      bit2  :f_reserved
      bit1  :f_read_only_intent
      bit1  :f_oledb
      bit4  :f_sql_type
    end

    struct  :option_flags_3 do
      bit3  :f_reserved
      bit1  :f_extension
      bit1  :f_unknown_collation_handling
      bit1  :f_user_instance
      bit1  :f_send_yukon_binary_xml
      bit1  :f_change_password
    end

    uint32  :client_time_zone
    uint32  :client_lcid

    # Offset/Length pairs for variable-length data
    buffer_field :hostname, encoding: Encoding::UTF_16LE
    buffer_field :username, encoding: Encoding::UTF_16LE
    buffer_field :password, encoding: Encoding::UTF_16LE, field_type: :ms_tds_login7_password
    buffer_field :app_name, encoding: Encoding::UTF_16LE
    buffer_field :server_name, encoding: Encoding::UTF_16LE
    buffer_field :unused, encoding: Encoding::ASCII_8BIT
    buffer_field :extension, encoding: Encoding::ASCII_8BIT, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_4 }
    buffer_field :clt_int_name, encoding: Encoding::UTF_16LE
    buffer_field :language, encoding: Encoding::UTF_16LE
    buffer_field :database, encoding: Encoding::UTF_16LE

    # Client MAC address (6 bytes)
    uint8_array  :client_id, initial_length: 6, initial_value: -> { Random.new.bytes(6).bytes }

    # More offset/length pairs
    buffer_field :sspi, encoding: Encoding::ASCII_8BIT
    buffer_field :attach_db_file, encoding: Encoding::UTF_16LE
    buffer_field :change_password, encoding: Encoding::UTF_16LE, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_2 }
    uint32  :cb_sspi_long, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_2 }

    string :buffer, initial_value: -> { build_buffer }, read_length: -> { packet_length - offset_of(buffer) }
    hide   :buffer

    def initialize_instance
      value = super

      self.server_name = self.hostname = Rex::Text.rand_text_alpha(rand(1..8))
      self.clt_int_name = self.app_name = Rex::Text.rand_text_alpha(rand(1..8))
      self.language = self.database = ""

      @@buffer_fields.each do |field_name|
        parameter = get_parameter(field_name)
        send("#{field_name}=", parameter) if parameter
      end

      value
    end

    def assign(value)
      super

      @@buffer_fields.each do |field_name|
        next unless value.key?(field_name)

        send("#{field_name}=", value[field_name])
      end
    end

    def initialize_shared_instance
      @@buffer_fields.each do |field_name|
        define_field_accessors_for2(field_name)
      end
      super
    end

    def do_read(val)
      value = super

      @@buffer_fields.each do |field_name|
        # the offset field's prefix is always ib_
        field_offset = send("ib_#{field_name}")
        # the size field's prefix depends on the data type, but it's always right after the offset
        field_size = send(field_names[field_names.index("ib_#{field_name}".to_sym) + 1])

        field_offset -= buffer.rel_offset
        if field_offset < 0
          instance_variable_set("@#{field_name}", nil)
          next
        end

        field_cls = BinData::RegisteredClasses.lookup(@@buffer_field_types[field_name])

        case @@buffer_field_types[field_name]
        when :string16, :ms_tds_login7_password
          field_size *= 2
          field_obj = field_cls.new(read_length: field_size)
        when :uint8_array
          field_obj = field_cls.new(read_until: :eof)
        end

        field_data = buffer[field_offset...(field_offset + field_size)]
        instance_variable_set("@#{field_name}", field_obj.read(field_data))
      end

      value
    end

    def snapshot
      snap = super
      @@buffer_fields.each do |field_name|
        snap[field_name] ||= send(field_name)&.snapshot
      end
      snap
    end

    private

    def build_buffer
      buf = ''
      @@buffer_fields.each do |field_name|
        field_value = send(field_name)
        buf << field_value.to_binary_s if field_value
      end
      buf
    end

    def buffer_field_offset(field)
      return nil unless instance_variable_get("@#{field}")

      offset = buffer.rel_offset
      @@buffer_fields.each do |field_name|
        break if field_name == field

        field_name = instance_variable_get("@#{field_name}")
        offset += field_name.num_bytes if field_name
      end

      offset
    end

    def define_field_accessors_for2(field_name)
      define_singleton_method(field_name) do
        instance_variable_get("@#{field_name}")
      end

      define_singleton_method("#{field_name}=") do |value|
        unless value.nil?
          field_cls = BinData::RegisteredClasses.lookup(@@buffer_field_types[field_name])
          value = field_cls.new(value)
        end

        instance_variable_set("@#{field_name}", value)
      end

      define_singleton_method("#{field_name}?") do
        !send(field_name).nil?
      end
    end
  end
end