module Net
module NTLM

  SSP_SIGN = "NTLMSSP\0"

  FLAGS = {
      :UNICODE              => 0x00000001,
      :OEM                  => 0x00000002,
      :REQUEST_TARGET       => 0x00000004,
      :MBZ9                 => 0x00000008,
      :SIGN                 => 0x00000010,
      :SEAL                 => 0x00000020,
      :NEG_DATAGRAM         => 0x00000040,
      :NETWARE              => 0x00000100,
      :NTLM                 => 0x00000200,
      :NEG_NT_ONLY          => 0x00000400,
      :MBZ7                 => 0x00000800,
      :DOMAIN_SUPPLIED      => 0x00001000,
      :WORKSTATION_SUPPLIED => 0x00002000,
      :LOCAL_CALL           => 0x00004000,
      :ALWAYS_SIGN          => 0x00008000,
      :TARGET_TYPE_DOMAIN   => 0x00010000,
      :NTLM2_KEY            => 0x00080000,
      :TARGET_INFO          => 0x00800000,
      :KEY128               => 0x20000000,
      :KEY_EXCHANGE         => 0x40000000,
      :KEY56                => 0x80000000
  }.freeze

  FLAG_KEYS = FLAGS.keys.sort{|a, b| FLAGS[a] <=> FLAGS[b] }

  DEFAULT_FLAGS = {
      :TYPE1 => FLAGS[:UNICODE] | FLAGS[:OEM] | FLAGS[:REQUEST_TARGET] | FLAGS[:NTLM] | FLAGS[:ALWAYS_SIGN] | FLAGS[:NTLM2_KEY],
      :TYPE2 => FLAGS[:UNICODE],
      :TYPE3 => FLAGS[:UNICODE] | FLAGS[:REQUEST_TARGET] | FLAGS[:NTLM] | FLAGS[:ALWAYS_SIGN] | FLAGS[:NTLM2_KEY]
  }


  # @private false
  class Message < FieldSet
    class << Message
      def parse(str)
        m = Type0.new
        m.parse(str)
        case m.type
        when 1
          t = Type1.new.parse(str)
        when 2
          t = Type2.new.parse(str)
        when 3
          t = Type3.new.parse(str)
        else
          raise ArgumentError, "unknown type: #{m.type}"
        end
        t
      end

      def decode64(str)
        parse(Base64.decode64(str))
      end
    end

    # @return [self]
    def parse(str)
      super

      while has_disabled_fields? && serialize.size < str.size
        # enable the next disabled field
        self.class.names.find { |name| !self[name].active && enable(name) }
        super
      end

      self
    end

    def has_flag?(flag)
      (self[:flag].value & FLAGS[flag]) == FLAGS[flag]
    end

    def set_flag(flag)
      self[:flag].value  |= FLAGS[flag]
    end

    def dump_flags
      FLAG_KEYS.each{ |k| print(k, "=", has_flag?(k), "\n") }
    end

    def serialize
      deflag
      super + security_buffers.map{|n, f| f.value}.join
    end

    def encode64
      Base64.encode64(serialize).gsub(/\n/, '')
    end

    def decode64(str)
      parse(Base64.decode64(str))
    end

    alias head_size size

    def data_size
      security_buffers.inject(0){|sum, a| sum += a[1].data_size}
    end

    def size
      head_size + data_size
    end


    def security_buffers
      @alist.find_all{|n, f| f.instance_of?(SecurityBuffer)}
    end

    def deflag
      security_buffers.inject(head_size){|cur, a|
        a[1].offset = cur
        cur += a[1].data_size
      }
    end

    def data_edge
      security_buffers.map{ |n, f| f.active ? f.offset : size}.min
    end

  end
end
end
