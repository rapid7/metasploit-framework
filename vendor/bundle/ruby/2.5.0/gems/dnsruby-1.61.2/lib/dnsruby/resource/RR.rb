# Superclass for all Dnsruby resource records.
#
# Represents a DNS RR (resource record) [RFC1035, section 3.2]
#
# Use Dnsruby::RR::create(...) to create a new RR record.
#
#   mx = Dnsruby::RR.create("example.com. 7200 MX 10 mailhost.example.com.")
#
#   rr = Dnsruby::RR.create({:name => "example.com", :type => "MX", :ttl => 7200,
#                                  :preference => 10, :exchange => "mailhost.example.com"})
#
#   s = rr.to_s # Get a String representation of the RR (in zone file format)
#   rr_again = Dnsruby::RR.create(s)
#

require 'dnsruby/code_mappers'

module Dnsruby
class RR

  include Comparable

  def <=>(other)
    #       return 1 if ((!other) || !(other.name) || !(other.type))
    #       return -1 if (!@name)
    if @name.canonical == other.name.canonical
      @type.code != other.type.code ? (@type.code <=> other.type.code) : (@rdata <=> other.rdata)
    else
      @name <=> other.name
    end
  end

  #  A regular expression which catches any valid resource record.
  @@RR_REGEX = Regexp.new("^\\s*(\\S+)\\s*(\\d+)?\\s*(#{Classes.regexp +
      "|CLASS\\d+"})?\\s*(#{Types.regexp + '|TYPE\\d+'})?\\s*([\\s\\S]*)\$") #:nodoc: all

  @@implemented_rr_map = nil

  # The Resource's domain name
  attr_reader :name

  # The Resource type
  attr_reader :type

  # The Resource class
  attr_reader :klass

  # The Resource Time-To-Live
  attr_accessor :ttl

  # The Resource data section
  attr_accessor :rdata

  def rdlength
    rdata.length
  end

  def name=(new_name)
    @name = new_name.kind_of?(Name) ? new_name : Name.create(new_name)
  end

  def type=(type)
    @type = Types.new(type)
  end
  alias :rr_type :type

  def klass=(klass)
    if @type != Types::OPT
      @klass = Classes.new(klass)
    else
      @klass = klass.is_a?(Classes) ? klass : Classes.new("CLASS#{klass}")
    end
  end

  def clone
    encoded = MessageEncoder.new { |encoder| encoder.put_rr(self, true) }.to_s
    MessageDecoder.new(encoded).get_rr
  end


  #  Determines if two Records could be part of the same RRset.
  #  This compares the name, type, and class of the Records; the ttl and
  #  rdata are not compared.
  def sameRRset(rec)
    if @klass != rec.klass || @name.downcase != rec.name.downcase
      return false
    elsif (rec.type == Types.RRSIG) && (@type == Types.RRSIG)
      return rec.type_covered == self.type_covered
    end
    [rec, self].each do |rr|
      if rr.type == Types::RRSIG
        return (@type == rr.type_covered) || (rec.type == rr.type_covered)
      end
    end
    @type == rec.type
  end

  def init_defaults
    #  Default to do nothing
  end

  private
  def initialize(*args) #:nodoc: all
    init_defaults
    if args.length > 0
      if args[0].class == Hash
        from_hash(args[0])
        return
      else
        @rdata = args[0]
        #           print "Loading RR from #{args[0]}, class : #{args[0].class}\n"
        if args[0].class == String
          from_string(args[0])
          return
        else
          from_data(args[0])
          return
        end
      end
    end
    #       raise ArgumentError.new("Don't call new! Use Dnsruby::RR::create() instead")
  end
  public

  def from_hash(hash) #:nodoc: all
    hash.keys.each do |param|
      send("#{param}=", hash[param])
    end
  end

  # Create a new RR from the hash. The name is required; all other fields are optional.
  # Type defaults to ANY and the Class defaults to IN. The TTL defaults to 0.
  #
  # If the type is specified, then it is necessary to provide ALL of the resource record fields which
  # are specific to that record; i.e. for
  # an MX record, you would need to specify the exchange and the preference
  #
  #    require 'Dnsruby'
  #    rr = Dnsruby::RR.new_from_hash({:name => "example.com"})
  #    rr = Dnsruby::RR.new_from_hash({:name => "example.com", :type => Types.MX, :ttl => 10, :preference => 5, :exchange => "mx1.example.com"})
  def RR.new_from_hash(inhash)
    hash = inhash.clone
    type = hash[:type] || Types::ANY
    klass = Classes.new(hash[:klass] || Classes::IN)
    ttl = hash[:ttl] || 0
    record_class = get_class(type, klass)
    record = record_class.new
    record.name = hash[:name]
    unless record.name.kind_of?(Name)
      record.name = Name.create(record.name)
    end
    record.ttl = ttl
    record.type = type
    record.klass = Classes.new(klass)
    hash.delete(:name)
    hash.delete(:type)
    hash.delete(:ttl)
    hash.delete(:klass)
    record.from_hash(hash)
    record
  end

  # Returns a Dnsruby::RR object of the appropriate type and
  # initialized from the string passed by the user.  The format of the
  # string is that used in zone files, and is compatible with the string
  # returned by Net::DNS::RR.inspect
  #
  # The name and RR type are required; all other information is optional.
  # If omitted, the TTL defaults to 0 and the RR class defaults to IN.
  #
  # All names must be fully qualified.  The trailing dot (.) is optional.
  #
  #
  #    a     = Dnsruby::RR.new_from_string("foo.example.com. 86400 A 10.1.2.3")
  #    mx    = Dnsruby::RR.new_from_string("example.com. 7200 MX 10 mailhost.example.com.")
  #    cname = Dnsruby::RR.new_from_string("www.example.com 300 IN CNAME www1.example.com")
  #    txt   = Dnsruby::RR.new_from_string('baz.example.com 3600 HS TXT "text record"')
  #
  #
  def RR.new_from_string(rrstring)
    #  strip out comments
    #  Test for non escaped ";" by means of the look-behind assertion
    #  (the backslash is escaped)
    rrstring = rrstring.gsub(/(\?<!\\);.*/o, '')

    matches = (/#{@@RR_REGEX}/xo).match(rrstring)
    unless matches
      raise "#{rrstring} did not match RR pattern. Please report this to the author!"
    end

    name    = matches[1]
    ttl     = matches[2].to_i || 0
    rrclass = matches[3] || ''
    rrtype  = matches[4] || ''
    rdata   = matches[5] || ''

    rdata.gsub!(/\s+$/o, '') if rdata

    #  RFC3597 tweaks
    #  This converts to known class and type if specified as TYPE###
    if rrtype  =~/^TYPE\d+/o
      rrtype  = Dnsruby::Types.typesbyval(Dnsruby::Types::typesbyname(rrtype))
    end
    if rrclass =~/^CLASS\d+/o
      rrclass = Dnsruby::Classes.classesbyval(Dnsruby::Classes::classesbyname(rrclass))
    end

    if rrtype == '' && rrclass == 'ANY'
      rrtype  = 'ANY'
      rrclass = 'IN'
    elsif rrclass == ''
      rrclass = 'IN'
    end

    if rrtype == ''
      rrtype = 'ANY'
    end

    unless %w(NAPTR TXT).include?(rrtype)
      if rdata
        rdata.gsub!('(', '')
        rdata.gsub!(')', '')
      end
    end

    test_length = ->(hexdump, rdlength) do
      if hexdump.length != rdlength * 2
        raise "#{rdata} is inconsistent; length should be #{rdlength * 2} but is #{hexdump.length}."
      end
    end

    pack_rdata = ->(regex) do
      rdata =~ regex
      matches = regex.match(rdata)
      rdlength = matches[1].to_i
      hexdump  = matches[2].gsub(/\s*/, '')

      test_length.(hexdump, rdlength)
      packed_rdata = [hexdump].pack('H*')

      [packed_rdata, rdlength]
    end

    if implemented_rrs.include?(rrtype) && rdata !~/^\s*\\#/o
      return _get_subclass(name, rrtype, rrclass, ttl, rdata)
    elsif implemented_rrs.include?(rrtype)   # A known RR type starting with \#
      packed_rdata, rdlength = pack_rdata.(/\\#\s+(\d+)\s+(.*)$/o)
      return new_from_data(name, rrtype, rrclass, ttl, rdlength, packed_rdata, 0) # rdata.length() - rdlength);
    elsif rdata =~ /\s*\\#\s+\d+\s+/o
      regex = /\\#\s+(\d+)\s+(.*)$/o
      # We are now dealing with the truly unknown.
      raise 'Expected RFC3597 representation of RDATA' unless rdata =~ regex
      packed_rdata, rdlength = pack_rdata.(regex)
      return new_from_data(name, rrtype, rrclass, ttl, rdlength, packed_rdata, 0) # rdata.length() - rdlength);
    else
      # God knows how to handle these...
      return _get_subclass(name, rrtype, rrclass, ttl, '')
    end
  end

  def RR.new_from_data(*args) #:nodoc: all
    name, rrtype, rrclass, ttl, rdlength, data, offset = args
    rdata = data ? data[offset, rdlength] : []
    decoder = MessageDecoder.new(rdata)
    record = get_class(rrtype, rrclass).decode_rdata(decoder)
    record.name = Name.create(name)
    record.ttl = ttl
    record.type = rrtype
    record.klass = Classes.new(rrclass)
    record
  end

  # Return an array of all the currently implemented RR types
  def RR.implemented_rrs
    @@implemented_rr_map ||= ClassHash.keys.map { |key| Dnsruby::Types.to_string(key[0]) }
  end

  class << self
    private
    def _get_subclass(name, rrtype, rrclass, ttl, rdata) #:nodoc: all
      return unless (rrtype!=nil)
      record = get_class(rrtype, rrclass).new(rdata)
      record.name = Name.create(name)
      record.ttl = ttl
      record.type = rrtype
      record.klass = Classes.new(rrclass)
      return record
    end
  end

  # Returns a string representation of the RR in zone file format
  def to_s
    s = name ? (name.to_s(true) + "\t") : ''
    s << [ttl, klass, type, rdata_to_string].map(&:to_s).join("\t")
  end

  # Get a string representation of the data section of the RR (in zone file format)
  def rdata_to_string
    (@rdata && @rdata.length > 0) ? @rdata : 'no rdata'
  end

  def from_data(data) #:nodoc: all
    #  to be implemented by subclasses
    raise NotImplementedError.new
  end

  def from_string(input) #:nodoc: all
    #  to be implemented by subclasses
    #       raise NotImplementedError.new
  end

  def encode_rdata(msg, canonical=false) #:nodoc: all
    #  to be implemented by subclasses
    raise EncodeError.new("#{self.class} is RR.")
  end

  def self.decode_rdata(msg) #:nodoc: all
    #  to be implemented by subclasses
    raise DecodeError.new("#{self.class} is RR.")
  end

  def ==(other)
    return false unless self.class == other.class

    ivars_to_compare = ->(object) do
      ivars = object.instance_variables.map { |var| var.to_s }
      ivars.delete '@ttl' # RFC 2136 section 1.1
      ivars.delete '@rdata'
      if self.type == Types.DS
        ivars.delete '@digest'
      end
      ivars.sort
    end

    get_instance_var_values = ->(object, ivar_names) do
      ivar_names.map { |ivar_name| object.instance_variable_get(ivar_name) }
    end

    self_ivars  = ivars_to_compare.(self)
    other_ivars = ivars_to_compare.(other)
    return false unless self_ivars == other_ivars

    self_values  = get_instance_var_values.(self, self_ivars)
    other_values = get_instance_var_values.(other, other_ivars)
    self_values == other_values
  end

  def eql?(other) #:nodoc:
    self == other
  end

  def hash # :nodoc:
    vars = (self.instance_variables - [:@ttl]).sort
    vars.inject(0) do |hash_value, var_name|
      hash_value ^ self.instance_variable_get(var_name).hash
    end
  end

  def self.find_class(type_value, class_value) # :nodoc: all
    if !! (ret = ClassHash[[type_value, class_value]])
      return ret
    elsif !! (val = ClassInsensitiveTypes[type_value])
      klass = Class.new(val)
      klass.const_set(:TypeValue, type_value)
      klass.const_set(:ClassValue, class_value)
      return klass
    else
      return Generic.create(type_value, class_value)
    end
  end

  # Get an RR of the specified type and class
  def self.get_class(type_value, class_value) #:nodoc: all
    if type_value == Types::OPT
      return Class.new(OPT)
    elsif type_value.class == Class
      type_value = type_value.const_get(:TypeValue)
      return find_class(type_value, Classes.to_code(class_value))
    else
      type_value = (type_value.class == Types) ? type_value.code : Types.new(type_value).code
      class_value = (class_value.class == Classes) ? class_value.code : Classes.new(class_value).code
      return find_class(type_value, class_value)
    end
  end


  # Create a new RR from the arguments, which can be either a String or a Hash.
  # See new_from_string and new_from_hash for details
  #
  #    a     = Dnsruby::RR.create('foo.example.com. 86400 A 10.1.2.3')
  #    mx    = Dnsruby::RR.create('example.com. 7200 MX 10 mailhost.example.com.')
  #    cname = Dnsruby::RR.create('www.example.com 300 IN CNAME www1.example.com')
  #    txt   = Dnsruby::RR.create('baz.example.com 3600 HS TXT 'text record'')
  #
  #    rr = Dnsruby::RR.create({:name => 'example.com'})
  #    rr = Dnsruby::RR.create({:name => 'example.com', :type => 'MX', :ttl => 10,
  #                                   :preference => 5, :exchange => 'mx1.example.com'})
  #
  def RR.create(*args)
    case args[0]
      when String
        new_from_string(args[0])
      when Hash
        new_from_hash(args[0])
      else
        new_from_data(args)
    end
  end

  def self.get_num(bytes)
    ret = 0
    shift = (bytes.length - 1) * 8
    bytes.each_byte do |byte|
      ret += byte.to_i << shift
      shift -= 8
    end
    ret
  end
end
end
