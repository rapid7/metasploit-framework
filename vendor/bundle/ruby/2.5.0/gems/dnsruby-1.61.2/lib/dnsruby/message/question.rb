# A Dnsruby::Question object represents a record in the
# question section of a DNS packet.
# 
# RFC 1035 Section 4.1.2
module Dnsruby
class Question

  #  The Question name
  attr_reader :qname
  #  The Question type
  attr_reader :qtype
  #  The Question class
  attr_reader :qclass

  #  Creates a question object from the domain, type, and class passed
  #  as arguments.
  # 
  #  If a String is passed in, a Name, IPv4 or IPv6 object is created.
  # 
  #  If an IPv4 or IPv6 object is used then the type is set to PTR.
  def initialize(qname, qtype = :not_provided, qclass = :not_provided)

    raise ArgumentError.new('qname must not be nil') if qname.nil?

    @qtype  = (qtype  == :not_provided) ? Types::A    : Types.new(qtype)
    @qclass = (qclass == :not_provided) ? Classes::IN : Classes.new(qclass)
    set_qname(qname, qtype == :not_provided)
  end

  def qtype=(qtype)
    @qtype = Types.new(qtype)
  end

  def qclass=(qclass)
    @qclass = Classes.new(qclass)
  end

  def set_qname(qname, write_PTR_to_qtype_if_ip = true)
    is_ipv4_addr_string = qname.is_a?(String) && IPv4::Regex.match(qname)
    is_ipv6_addr_string = qname.is_a?(String) && IPv6::Regex.match(qname)
    is_ip_addr_string = is_ipv4_addr_string || is_ipv6_addr_string

    is_ip_addr = [IPv4, IPv6].any? { |klass| qname.is_a?(klass) }

    if is_ipv4_addr_string
      @qname = IPv4.create(qname).to_name
    elsif is_ipv6_addr_string
      @qname = IPv6.create(qname).to_name
    else
      @qname = Name.create(qname)
    end

    #  If the name looks like an IP address then do an appropriate
    #  PTR query, unless the user specified the qtype
    if write_PTR_to_qtype_if_ip && (is_ip_addr || is_ip_addr_string)
      @qtype = Types.PTR
    end
    @qname.absolute = true
  end

  def qname=(qname)
    set_qname(qname, true)
  end

  def ==(other)
    other.is_a?(Question) &&
        self.qname  == other.qname  &&
        self.qtype  == other.qtype  &&
        self.qclass == Classes.new(other.qclass)
  end

  #  Returns a string representation of the question record.
  def to_s
    "#{@qname}.\t#{@qclass.string}\t#{@qtype.string}"
  end

  #  For Updates, the qname field is redefined to zname (RFC2136, section 2.3)
  alias zname qname
  #  For Updates, the qtype field is redefined to ztype (RFC2136, section 2.3)
  alias ztype qtype
  #  For Updates, the qclass field is redefined to zclass (RFC2136, section 2.3)
  alias zclass qclass

  alias type qtype
end
end