module Dnsruby

# The header portion of a DNS packet
# 
# RFC 1035 Section 4.1.1
class Header
  MAX_ID = 65535

  #  The header ID
  attr_accessor :id

  #  The query response flag
  attr_accessor :qr

  #  Authoritative answer flag
  attr_accessor :aa

  #  Truncated flag
  attr_accessor :tc

  #  Recursion Desired flag
  attr_accessor :rd

  #  The Checking Disabled flag
  attr_accessor :cd

  #  The Authenticated Data flag
  #  Relevant in DNSSEC context.
  #  (The AD bit is only set on answers where signatures have been
  #  cryptographically verified or the server is authoritative for the data
  #  and is allowed to set the bit by policy.)
  attr_accessor :ad

  #  The query response flag
  attr_accessor :qr

  #  Recursion available flag
  attr_accessor :ra

  #  Query response code
  #  deprecated - use Message#rcode
  #     attr_reader :rcode

  #  This new get_header_rcode method is intended for use only by the Message class.
  #  This is because the Message OPT section may contain an extended rcode (see
  #  RFC 2671 section 4.6). Using the header rcode only ignores this extension, and
  #  is not recommended.
  def get_header_rcode
    @rcode
  end

  #  The header opcode
  attr_reader :opcode

  #  The number of records in the question section of the message
  attr_accessor :qdcount
  #  The number of records in the authoriy section of the message
  attr_accessor :nscount
  #  The number of records in the answer section of the message
  attr_accessor :ancount
  #  The number of records in the additional record section og the message
  attr_accessor :arcount

  def initialize(*args)
    if (args.length == 0)
      @id = rand(MAX_ID)
      @qr = false
      @opcode = OpCode.Query
      @aa = false
      @ad = false
      @tc = false
      @rd = false # recursion desired
      @ra = false # recursion available
      @cd = false
      @rcode = RCode.NoError
      @qdcount = 0
      @nscount = 0
      @ancount = 0
      @arcount = 0
    elsif args.length == 1
      decode(args[0])
    end
  end

  def opcode=(op)
    @opcode = OpCode.new(op)
  end

  def rcode=(rcode)
    @rcode = RCode.new(rcode)
  end

  def Header.new_from_data(data)
    header = Header.new
    MessageDecoder.new(data) { |msg| header.decode(msg) }
    header
  end

  def data
    MessageEncoder.new { |msg| self.encode(msg) }.to_s
  end

  def encode(msg)
    msg.put_pack('nnnnnn',
                 @id,
                 (@qr ? 1:0) << 15 |
                     (@opcode.code & 15) << 11 |
                     (@aa ? 1:0) << 10 |
                     (@tc ? 1:0) << 9 |
                     (@rd ? 1:0) << 8 |
                     (@ra ? 1:0) << 7 |
                     (@ad ? 1:0) << 5 |
                     (@cd ? 1:0) << 4 |
                     (@rcode.code & 15),
                 @qdcount,
                 @ancount,
                 @nscount,
                 @arcount)
  end

  def Header.decrement_arcount_encoded(bytes)
    header = Header.new
    header_end = 0
    MessageDecoder.new(bytes) do |msg|
      header.decode(msg)
      header_end = msg.index
    end
    header.arcount -= 1
    bytes[0, header_end] = MessageEncoder.new { |msg| header.encode(msg) }.to_s
    bytes
  end

  def ==(other)
    @qr == other.qr &&
        @opcode == other.opcode &&
        @aa == other.aa &&
        @tc == other.tc &&
        @rd == other.rd &&
        @ra == other.ra &&
        @cd == other.cd &&
        @ad == other.ad &&
        @rcode == other.get_header_rcode
  end

  def to_s
    to_s_with_rcode(@rcode)
  end

  def old_to_s
    old_to_s_with_rcode(@rcode)
  end

  def to_s_with_rcode(rcode)

    if @opcode == OpCode::Update
      s = ";; id = #{@id}\n"
      s << ";; qr = #{@qr}    opcode = #{@opcode.string}    rcode = #{@rcode.string}\n"
      s << ";; zocount = #{@qdcount}  "
      s <<  "prcount = #{@ancount}  "
      s <<  "upcount = #{@nscount}  "
      s <<  "adcount = #{@arcount}\n"
      s
    else

      flags_str = begin
        flags = []
        flags << 'qr' if @qr
        flags << 'aa' if @aa
        flags << 'tc' if @tc
        flags << 'rd' if @rd
        flags << 'ra' if @ra
        flags << 'ad' if @ad
        flags << 'cd' if @cd

        ";; flags: #{flags.join(' ')}; "
      end

      head_line_str =
          ";; ->>HEADER<<- opcode: #{opcode.string.upcase}, status: #{@rcode.string}, id: #{@id}\n"

      section_counts_str =
          "QUERY: #{@qdcount}, ANSWER: #{@ancount}, AUTHORITY: #{@nscount}, ADDITIONAL: #{@arcount}\n"

      head_line_str + flags_str + section_counts_str
    end
  end


  def old_to_s_with_rcode(rcode)
    retval = ";; id = #{@id}\n"

    if (@opcode == OpCode::Update)
      retval += ";; qr = #{@qr}    " \
        "opcode = #{@opcode.string}    "\
        "rcode = #{@rcode.string}\n"

      retval += ";; zocount = #{@qdcount}  "\
        "prcount = #{@ancount}  " \
        "upcount = #{@nscount}  "  \
        "adcount = #{@arcount}\n"
    else
      retval += ";; qr = #{@qr}    "  \
        "opcode = #{@opcode.string}    " \
        "aa = #{@aa}    "  \
        "tc = #{@tc}    " \
        "rd = #{@rd}\n"

      retval += ";; ra = #{@ra}    " \
        "ad = #{@ad}    "  \
        "cd = #{@cd}    "  \
        "rcode  = #{rcode.string}\n"

      retval += ";; qdcount = #{@qdcount}  " \
        "ancount = #{@ancount}  " \
        "nscount = #{@nscount}  " \
        "arcount = #{@arcount}\n"
    end

    retval
  end

  def decode(msg)
    @id, flag, @qdcount, @ancount, @nscount, @arcount =
        msg.get_unpack('nnnnnn')
    @qr = ((flag >> 15) & 1) == 1
    @opcode = OpCode.new((flag >> 11) & 15)
    @aa = ((flag >> 10) & 1) == 1
    @tc = ((flag >> 9)  & 1) == 1
    @rd = ((flag >> 8)  & 1) == 1
    @ra = ((flag >> 7)  & 1) == 1
    @ad = ((flag >> 5)  & 1) == 1
    @cd = ((flag >> 4)  & 1) == 1
    @rcode = RCode.new(flag & 15)
  end

  alias zocount qdcount
  alias zocount= qdcount=

  alias prcount ancount
  alias prcount= ancount=

  alias upcount nscount
  alias upcount= nscount=

  alias adcount arcount
  alias adcount= arcount=

end
end