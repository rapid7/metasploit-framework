# -*- coding: binary -*-
require 'packetfu/protos/tcp/option'

module PacketFu

  class TcpOptions < Array

    include StructFu

    # If args[:pad] is set, the options line is automatically padded out
    # with NOPs. 
    def to_s(args={})
      opts = self.map {|x| x.to_s}.join
      if args[:pad]
        unless (opts.size % 4).zero?
          (4 - (opts.size % 4)).times { opts << "\x01" }
        end
      end
      opts
    end

    # Reads a string to populate the object.
    def read(str)
      self.clear 
      PacketFu.force_binary(str)
      return self if(!str.respond_to? :to_s || str.nil?)
      i = 0
      while i < str.to_s.size
        this_opt = case str[i,1].unpack("C").first
                   when 0; ::PacketFu::TcpOption::EOL.new
                   when 1; ::PacketFu::TcpOption::NOP.new
                   when 2; ::PacketFu::TcpOption::MSS.new
                   when 3; ::PacketFu::TcpOption::WS.new
                   when 4; ::PacketFu::TcpOption::SACKOK.new
                   when 5; ::PacketFu::TcpOption::SACK.new
                   when 6; ::PacketFu::TcpOption::ECHO.new
                   when 7; ::PacketFu::TcpOption::ECHOREPLY.new
                   when 8; ::PacketFu::TcpOption::TS.new
                   else; ::PacketFu::TcpOption.new
                   end
        this_opt.read str[i,str.size]
        unless this_opt.has_optlen?
          this_opt.value = nil
          this_opt.optlen = nil
        end
        self << this_opt
        i += this_opt.sz
      end
      self
    end

    # Decode parses the TcpOptions object's member options, and produces a
    # human-readable string by iterating over each element's decode() function.
    # If TcpOptions elements were not initially created as TcpOptions, an
    # attempt will be made to convert them. 
    #
    # The output of decode is suitable as input for TcpOptions#encode.
    def decode
      decoded = self.map do |x| 
        if x.kind_of? TcpOption
          x.decode
        else
          x = TcpOptions.new.read(x).decode
        end
      end
      decoded.join(",")
    end

    # Encode takes a human-readable string and appends the corresponding
    # binary options to the TcpOptions object. To completely replace the contents
    # of the object, use TcpOptions#encode! instead.
    # 
    # Options are comma-delimited, and are identical to the output of the
    # TcpOptions#decode function. Note that the syntax can be unforgiving, so
    # it may be easier to create the subclassed TcpOptions themselves directly,
    # but this method can be less typing if you know what you're doing.
    # 
    # Note that by using TcpOptions#encode, strings supplied as values which
    # can be converted to numbers will be converted first.
    #
    # === Example
    #
    #   t = TcpOptions.new
    #   t.encode("MS:1460,WS:6")
    #		t.to_s # => "\002\004\005\264\002\003\006"
    #		t.encode("NOP")
    #		t.to_s # => "\002\004\005\264\002\003\006\001"
    def encode(str)
      opts = str.split(/[\s]*,[\s]*/)
      opts.each do |o|
        kind,value = o.split(/[\s]*:[\s]*/)
        klass = TcpOption.const_get(kind.upcase)
        value = value.to_i if value =~ /^[0-9]+$/
        this_opt = klass.new
        this_opt.encode(value)
        self << this_opt
      end
      self
    end

    # Like TcpOption#encode, except the entire contents are replaced.
    def encode!(str)
      self.clear if self.size > 0
      encode(str)
    end
  end
end
