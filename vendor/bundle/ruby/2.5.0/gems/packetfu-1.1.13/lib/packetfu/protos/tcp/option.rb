# -*- coding: binary -*-
module PacketFu
  # TcpOption is the base class for all TCP options. Note that TcpOption#len 
  # returns the size of the entire option, while TcpOption#optlen is the struct 
  # for the TCP Option Length field.
  #
  # Subclassed options should set the correct TcpOption#kind by redefining 
  # initialize. They should also deal with various value types there by setting
  # them explicitly with an accompanying StructFu#typecast for the setter. 
  #
  # By default, values are presumed to be strings, unless they are Numeric, in
  # which case a guess is made to the width of the Numeric based on the given
  # optlen. 
  #
  # Note that normally, optlen is /not/ enforced for directly setting values,
  # so the user is perfectly capable of setting incorrect lengths.
  class TcpOption < Struct.new(:kind, :optlen, :value)

    include StructFu

    def initialize(args={})
      super(
        Int8.new(args[:kind]),
        Int8.new(args[:optlen])
      )
      if args[:value].kind_of? Numeric
        self[:value] = case args[:optlen]
                       when 3; Int8.new(args[:value])
                       when 4; Int16.new(args[:value])
                       when 6; Int32.new(args[:value])
                       else; StructFu::String.new.read(args[:value])
                       end
      else
        self[:value] = StructFu::String.new.read(args[:value])
      end
    end

    # Returns the object in string form.
    def to_s
      self[:kind].to_s + 
      (self[:optlen].value.nil? ? nil : self[:optlen]).to_s +
      (self[:value].nil? ? nil : self[:value]).to_s
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:kind].read(str[0,1])
      if str[1,1]
        self[:optlen].read(str[1,1])
        if str[2,1] && optlen.value > 2
          self[:value].read(str[2,optlen.value-2])
        end
      end
      self
    end

    # The default decode for an unknown option. Known options should redefine this.
    def decode
      unk = "unk-#{self.kind.to_i}"
      (self[:optlen].to_i > 2 && self[:value].to_s.size > 1) ? [unk,self[:value]].join(":") : unk
    end

    # Setter for the "kind" byte of this option.
    def kind=(i); typecast i; end
    # Setter for the "option length" byte for this option.
    def optlen=(i); typecast i; end

    # Setter for the value of this option. 
    def value=(i)
      if i.kind_of? Numeric
        typecast i
      elsif i.respond_to? :to_s
        self[:value] = i
      else
        self[:value] = ''
      end
    end

    # Generally, encoding a value is going to be just a read. Some
    # options will treat things a little differently; TS for example,
    # takes two values and concatenates them.
    def encode(str)
      self[:value] = self.class.new(:value => str).value
    end

    # Returns true if this option has an optlen. Some don't.
    def has_optlen?
      (kind.value && kind.value < 2) ? false : true
    end
    
    # Returns true if this option has a value. Some don't.
    def has_value?
      (value.respond_to? :to_s && value.to_s.size > 0) ? false : true
    end

    # End of Line option. Usually used to terminate a string of options.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option000.htm
    class EOL < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 0)
        )
      end

      def decode
        "EOL"
      end

    end

    # No Operation option. Usually used to pad out options to fit a 4-byte alignment.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option001.htm
    class NOP < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 1)
        )
      end

      def decode
        "NOP"
      end

    end

    # Maximum Segment Size option.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option002.htm
    class MSS < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 2,
                     :optlen => 4
                    )
        )
        self[:value] = Int16.new(args[:value])
      end

      def value=(i); typecast i; end

      # MSS options with lengths other than 4 are malformed.
      def decode
        if self[:optlen].to_i == 4
          "MSS:#{self[:value].to_i}"
        else
          "MSS-bad:#{self[:value]}"
        end
      end

    end

    # Window Size option.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option003.htm
    class WS < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 3,
                     :optlen => 3
                    )
        )
        self[:value] = Int8.new(args[:value])
      end

      def value=(i); typecast i; end

      # WS options with lengths other than 3 are malformed.
      def decode
        if self[:optlen].to_i == 3
          "WS:#{self[:value].to_i}"
        else
          "WS-bad:#{self[:value]}"
        end
      end

    end

    # Selective Acknowlegment OK option.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option004.htm
    class SACKOK < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 4,
                     :optlen => 2)
        )
      end

      # SACKOK options with sizes other than 2 are malformed.
      def decode
        if self[:optlen].to_i == 2
          "SACKOK"
        else
          "SACKOK-bad:#{self[:value]}"
        end
      end

    end

    # Selective Acknowledgement option.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option004.htm
    #
    # Note that SACK always takes its optlen from the size of the string.
    class SACK < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 5,
                     :optlen => ((args[:value] || "").size + 2)
                    )
        )
      end

      def optlen=(i); typecast i; end

      def value=(i)
        self[:optlen] = Int8.new(i.to_s.size + 2)
        self[:value] = StructFu::String.new(i)
      end

      def decode
          "SACK:#{self[:value]}"
      end

      def encode(str)
        temp_obj = self.class.new(:value => str)
        self[:value] = temp_obj.value
        self[:optlen] = temp_obj.optlen.value
        self
      end

    end

    # Echo option.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option006.htm
    class ECHO < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 6,
                     :optlen => 6
                    )
        )
      end

      # ECHO options with lengths other than 6 are malformed.
      def decode
        if self[:optlen].to_i == 6
          "ECHO:#{self[:value]}"
        else
          "ECHO-bad:#{self[:value]}"
        end
      end

    end

    # Echo Reply option.
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option007.htm
    class ECHOREPLY < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 7,
                     :optlen => 6
                    )
        )
      end

      # ECHOREPLY options with lengths other than 6 are malformed.
      def decode
        if self[:optlen].to_i == 6
          "ECHOREPLY:#{self[:value]}"
        else
          "ECHOREPLY-bad:#{self[:value]}"
        end
      end

    end

    # Timestamp option
    #
    # http://www.networksorcery.com/enp/protocol/tcp/option008.htm
    class TS < TcpOption
      def initialize(args={})
        super(
          args.merge(:kind => 8,
                     :optlen => 10
                    )
        )
        self[:value] = StructFu::String.new.read(args[:value] || "\x00" * 8) 
      end

      # TS options with lengths other than 10 are malformed.
      def decode
        if self[:optlen].to_i == 10
          val1,val2 = self[:value].unpack("NN")
          "TS:#{val1};#{val2}"
        else
          "TS-bad:#{self[:value]}"
        end
      end

      # TS options are in the format of "TS:[timestamp value];[timestamp secret]" Both
      # should be written as decimal numbers.
      def encode(str)
        if str =~ /^([0-9]+);([0-9]+)$/
          tsval,tsecr = str.split(";").map {|x| x.to_i}
          if tsval <= 0xffffffff && tsecr <= 0xffffffff
            self[:value] = StructFu::String.new([tsval,tsecr].pack("NN"))
          else
            self[:value] = StructFu::String.new(str)
          end
        else
          self[:value] = StructFu::String.new(str)
        end
      end

    end
  end
end
