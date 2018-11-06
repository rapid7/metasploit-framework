class Filesize
  include Comparable

  TYPE_PREFIXES = {
    # Unit prefixes used for SI file sizes.
    :SI => %w{k M G T P E Z Y},
    # Unit prefixes used for binary file sizes.
    :BINARY => %w{Ki Mi Gi Ti Pi Ei Zi Yi}
  }

  # @deprecated Please use TYPE_PREFIXES[:SI] instead
  PREFIXES = TYPE_PREFIXES[:SI]

  # Set of rules describing file sizes according to SI units.
  SI = {
    :regexp => /^([\d,.]+)?[[:space:]]?([kmgtpezy]?)b?$/i,
    :multiplier => 1000,
    :prefixes => TYPE_PREFIXES[:SI],
    :presuffix => '' # deprecated
  }
  # Set of rules describing file sizes according to binary units.
  BINARY = {
    :regexp => /^([\d,.]+)?[[:space:]]?(?:([kmgtpezy])i)?b?$/i,
    :multiplier => 1024,
    :prefixes => TYPE_PREFIXES[:BINARY],
    :presuffix => 'i' # deprecated
  }

  # Set default precision
  PRECISION = 2

  # @param [Number] size A file size, in bytes.
  # @param [SI, BINARY] type Which type to use for conversions.
  def initialize(size, type = BINARY)
    @bytes = size.to_i
    @type  = type
  end

  # @return [Number] Returns the size in bytes.
  def to_i
    @bytes
  end
  alias_method :to_int, :to_i

  # @param [String] unit Which unit to convert to.
  # @return [Float] Returns the size in a given unit.
  def to(unit = 'B')
    to_parts = self.class.parse(unit)
    prefix   = to_parts[:prefix]

    if prefix == 'B' or prefix.empty?
      return to_i.to_f
    end

    to_type = to_parts[:type]
    size    = @bytes

    pos = (@type[:prefixes].map { |s| s[0].chr.downcase }.index(prefix.downcase) || -1) + 1

    size = size/(to_type[:multiplier].to_f**(pos)) unless pos < 1
  end
  alias_method :to_f, :to

  # @param (see #to_f)
  # @return [String] Same as {#to_f}, but as a string, with the unit appended.
  # @see #to_f
  def to_s(unit = 'B', args = {})
    precision = args[:precision] || PRECISION
    
    "%.#{precision}f %s" % [to(unit).to_f.to_s, unit]
  end

  # Same as {#to_s} but with an automatic determination of the most
  # sensible unit.
  #
  # @return [String]
  # @see #to_s
  def pretty(args = {})
    size = @bytes
    if size < @type[:multiplier]
      unit = "B"
    else
      pos = (Math.log(size) / Math.log(@type[:multiplier])).floor
      pos = @type[:prefixes].size-1 if pos > @type[:prefixes].size - 1

      unit = @type[:prefixes][pos-1] + "B"
    end

    to_s(unit, args)
  end

  # @return [Filesize]
  def +(other)
    self.class.new(@bytes + other.to_i, @type)
  end

  # @return [Filesize]
  def -(other)
    self.class.new(@bytes - other.to_i, @type)
  end

  # @return [Filesize]
  def *(other)
    self.class.new(@bytes * other.to_i, @type)
  end

  # @return [Filesize]
  def /(other)
    result = @bytes / other.to_f
    if other.is_a? Filesize
      result
    else
      self.class.new(result, @type)
    end
  end

  def <=>(other)
    self.to_i <=> other.to_i
  end

  # @return [Array<self, other>]
  # @api private
  def coerce(other)
    return self, other
  end

  class << self
    # Parses a string, which describes a file size, and returns a
    # Filesize object.
    #
    # @param [String] arg A file size to parse.
    # @raise [ArgumentError] Raised if the file size cannot be parsed properly.
    # @return [Filesize]
    def from(arg)
      parts  = parse(arg)
      prefix = parts[:prefix]
      size   = parts[:size]
      type   = parts[:type]

      raise ArgumentError, "Unparseable filesize: #{arg}" unless type

      offset = (type[:prefixes].map { |s| s[0].chr.downcase }.index(prefix.downcase) || -1) + 1

      new(size * (type[:multiplier] ** (offset)), type)
    end

    # @return [Hash<:prefix, :size, :type>]
    # @api private
    def parse(string)
      type = nil
      # in this order, so we prefer binary :)
      [BINARY, SI].each { |_type|
        if string =~ _type[:regexp]
          type    =  _type
          break
        end
      }

      prefix = $2 || ''
      size   = ($1 || 0).to_f

      return { :prefix => prefix, :size => size, :type => type}
    end
  end

  # The size of a floppy disk
  Floppy = Filesize.from("1474 KiB")
  # The size of a CD
  CD     = Filesize.from("700 MB")
  # The size of a common DVD
  DVD_5  = Filesize.from("4.38 GiB")
  # The same as a DVD 5
  DVD    = DVD_5
  # The size of a single-sided dual-layer DVD
  DVD_9  = Filesize.from("7.92 GiB")
  # The size of a double-sided single-layer DVD
  DVD_10 = DVD_5 * 2
  # The size of a double-sided DVD, combining a DVD-9 and a DVD-5
  DVD_14 = DVD_9 + DVD_5
  # The size of a double-sided dual-layer DVD
  DVD_18 = DVD_14 * 2
  # The size of a Zip disk
  ZIP    = Filesize.from("100 MB")
end
