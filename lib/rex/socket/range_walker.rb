# -*- coding: binary -*-
require 'rex/socket'

module Rex
module Socket

###
#
# This class provides an interface to enumerating an IP range
#
# This class uses start,stop pairs to represent ranges of addresses.  This
# is very efficient for large numbers of consecutive addresses, and not
# show-stoppingly inefficient when storing a bunch of non-consecutive
# addresses, which should be a somewhat unusual case.
#
# @example
#   r = RangeWalker.new("10.1,3.1-7.1-255")
#   r.include?("10.3.7.255") #=> true
#   r.length #=> 3570
#   r.each do |addr|
#     # do something with the address
#   end
###
class RangeWalker

  # The total number of IPs within the range
  #
  # @return [Fixnum]
  attr_reader :length

  # for backwards compatibility
  alias :num_ips :length

  # A list of the {Range ranges} held in this RangeWalker
  # @return [Array]
  attr_reader :ranges

  # Initializes a walker instance using the supplied range
  #
  # @param parseme [RangeWalker,String]
  def initialize(parseme)
    if parseme.is_a? RangeWalker
      @ranges = parseme.ranges.dup
    else
      @ranges = parse(parseme)
    end
    reset
  end

  #
  # Calls the instance method
  #
  # This is basically only useful for determining if a range can be parsed
  #
  # @return (see #parse)
  def self.parse(parseme)
    self.new.parse(parseme)
  end

  #
  # Turn a human-readable range string into ranges we can step through one address at a time.
  #
  # Allow the following formats:
  #   "a.b.c.d e.f.g.h"
  #   "a.b.c.d, e.f.g.h"
  # where each chunk is CIDR notation, (e.g. '10.1.1.0/24') or a range in nmap format (see {#expand_nmap})
  #
  # OR this format
  #   "a.b.c.d-e.f.g.h"
  # where a.b.c.d and e.f.g.h are single IPs and the second must be
  # bigger than the first.
  #
  # @param parseme [String]
  # @return [self]
  # @return [false] if +parseme+ cannot be parsed
  def parse(parseme)
    return nil if not parseme
    ranges = []
    parseme.split(', ').map{ |a| a.split(' ') }.flatten.each do |arg|
      opts = {}

      # Handle IPv6 first (support ranges, but not CIDR)
      if arg.include?(":")
        addrs = arg.split('-', 2)

        # Handle a single address
        if addrs.length == 1
          addr, scope_id = addrs[0].split('%')
          opts[:scope_id] = scope_id if scope_id
          opts[:ipv6] = true

          return false unless Rex::Socket.is_ipv6?(addr)
          addr = Rex::Socket.addr_atoi(addr)
          ranges.push(Range.new(addr, addr, opts))
          next
        end

        addr1, scope_id = addrs[0].split('%')
        opts[:scope_id] = scope_id if scope_id

        addr2, scope_id = addrs[0].split('%')
        ( opts[:scope_id] ||= scope_id ) if scope_id

        # Both have to be IPv6 for this to work
        return false unless (Rex::Socket.is_ipv6?(addr1) && Rex::Socket.is_ipv6?(addr2))

        # Handle IPv6 ranges in the form of 2001::1-2001::10
        addr1 = Rex::Socket.addr_atoi(addr1)
        addr2 = Rex::Socket.addr_atoi(addr2)

        ranges.push(Range.new(addr1, addr2, opts))
        next

      # Handle IPv4 CIDR
      elsif arg.include?("/")
        # Then it's CIDR notation and needs special case
        return false if arg =~ /[,-]/ # Improper CIDR notation (can't mix with 1,3 or 1-3 style IP ranges)
        return false if arg.scan("/").size > 1 # ..but there are too many slashes
        ip_part,mask_part = arg.split("/")
        return false if ip_part.nil? or ip_part.empty? or mask_part.nil? or mask_part.empty?
        return false if mask_part !~ /^[0-9]{1,2}$/ # Illegal mask -- numerals only
        return false if mask_part.to_i > 32 # This too -- between 0 and 32.
        if ip_part =~ /^\d{1,3}(\.\d{1,3}){1,3}$/
          return false unless ip_part =~ Rex::Socket::MATCH_IPV4
        end
        begin
          Rex::Socket.getaddress(ip_part) # This allows for "www.metasploit.com/24" which is fun.
        rescue Resolv::ResolvError, ::SocketError, Errno::ENOENT
          return false # Can't resolve the ip_part, so bail.
        end

        expanded = expand_cidr(arg)
        if expanded
          ranges.push(expanded)
        else
          return false
        end

      # Handle hostnames
      elsif arg =~ /[^-0-9,.*]/
        # Then it's a domain name and we should send it on to addr_atoi
        # unmolested to force a DNS lookup.
        begin
          ranges += Rex::Socket.addr_atoi_list(arg).map { |a| Range.new(a, a, opts) }
        rescue Resolv::ResolvError, ::SocketError, Errno::ENOENT
          return false
        end

      # Handle IPv4 ranges
      elsif arg =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/

        # Then it's in the format of 1.2.3.4-5.6.7.8
        # Note, this will /not/ deal with DNS names, or the fancy/obscure 10...1-10...2
        begin
          start, stop = Rex::Socket.addr_atoi($1), Rex::Socket.addr_atoi($2)
          return false if start > stop # The end is greater than the beginning.
          ranges.push(Range.new(start, stop, opts))
        rescue Resolv::ResolvError, ::SocketError, Errno::ENOENT
          return false
        end
      else
        # Returns an array of ranges
        expanded = expand_nmap(arg)
        if expanded
          expanded.each { |r| ranges.push(r) }
        end
      end
    end

    # Remove any duplicate ranges
    ranges = ranges.uniq

    return ranges
  end

  #
  # Resets the subnet walker back to its original state.
  #
  # @return [self]
  def reset
    return false if not valid?
    @curr_range = 0
    @curr_addr = @ranges.first.start
    @length = 0
    @ranges.each { |r| @length += r.length }

    self
  end

  # Returns the next IP address.
  #
  # @return [String] The next address in the range
  def next_ip
    return false if not valid?
    if (@curr_addr > @ranges[@curr_range].stop)
      if (@curr_range >= @ranges.length - 1)
        return nil
      end
      @curr_range += 1
      @curr_addr = @ranges[@curr_range].start
    end
    addr = Rex::Socket.addr_itoa(@curr_addr, @ranges[@curr_range].ipv6?)

    if @ranges[@curr_range].options[:scope_id]
      addr = addr + '%' + @ranges[@curr_range].options[:scope_id]
    end

    @curr_addr += 1
    return addr
  end

  alias :next :next_ip

  # Whether this RangeWalker's ranges are valid
  def valid?
    (@ranges && !@ranges.empty?)
  end

  # Returns true if the argument is an ip address that falls within any of
  # the stored ranges.
  #
  # @return [true] if this RangeWalker contains +addr+
  # @return [false] if not
  def include?(addr)
    return false if not @ranges
    if (addr.is_a? String)
      addr = Rex::Socket.addr_atoi(addr)
    end
    @ranges.map { |r|
      if addr.between?(r.start, r.stop)
        return true
      end
    }
    return false
  end

  #
  # Returns true if this RangeWalker includes *all* of the addresses in the
  # given RangeWalker
  #
  # @param other [RangeWalker]
  def include_range?(other)
    return false if (!@ranges || @ranges.empty?)
    return false if !other.ranges || other.ranges.empty?

    # Check that all the ranges in +other+ fall within at least one of
    # our ranges.
    other.ranges.all? do |other_range|
      ranges.any? do |range|
        other_range.start.between?(range.start, range.stop) && other_range.stop.between?(range.start, range.stop)
      end
    end
  end

  #
  # Calls the given block with each address. This is basically a wrapper for
  # {#next_ip}
  #
  # @return [self]
  def each(&block)
    while (ip = next_ip)
      block.call(ip)
    end
    reset

    self
  end

  #
  # Returns an Array with one element, a {Range} defined by the given CIDR
  # block.
  #
  # @see Rex::Socket.cidr_crack
  # @param arg [String] A CIDR range
  # @return [Range]
  # @return [false] if +arg+ is not valid CIDR notation
  def expand_cidr(arg)
    start,stop = Rex::Socket.cidr_crack(arg)
    if !start or !stop
      return false
    end
    range = Range.new
    range.start = Rex::Socket.addr_atoi(start)
    range.stop = Rex::Socket.addr_atoi(stop)
    range.options = { :ipv6 => (arg.include?(":")) }

    return range
  end

  #
  # Expands an nmap-style host range x.x.x.x where x can be simply "*" which
  # means 0-255 or any combination and repitition of:
  #    i,n
  #    n-m
  #    i,n-m
  #    n-m,i
  # ensuring that n is never greater than m.
  #
  # non-unique elements will be removed
  #  e.g.:
  #    10.1.1.1-3,2-2,2 =>  ["10.1.1.1", "10.1.1.2", "10.1.1.3"]
  #    10.1.1.1-3,7 =>  ["10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.7"]
  #
  # Returns an array of Ranges
  #
  def expand_nmap(arg)
    # Can't really do anything with IPv6
    return false if arg.include?(":")

    # nmap calls these errors, but it's hard to catch them with our
    # splitting below, so short-cut them here
    return false if arg.include?(",-") or arg.include?("-,")

    bytes = []
    sections = arg.split('.')
    if sections.length != 4
      # Too many or not enough dots
      return false
    end
    sections.each { |section|
      if section.empty?
        # pretty sure this is an unintentional artifact of the C
        # functions that turn strings into ints, but it sort of makes
        # sense, so why not
        #   "10...1" => "10.0.0.1"
        section = "0"
      end

      if section == "*"
        # I think this ought to be 1-254, but this is how nmap does it.
        section = "0-255"
      elsif section.include?("*")
        return false
      end

      # Break down the sections into ranges like so
      # "1-3,5-7" => ["1-3", "5-7"]
      ranges = section.split(',', -1)
      sets = []
      ranges.each { |r|
        bounds = []
        if r.include?('-')
          # Then it's an actual range, break it down into start,stop
          # pairs:
          #   "1-3" => [ 1, 3 ]
          # if the lower bound is empty, start at 0
          # if the upper bound is empty, stop at 255
          #
          bounds = r.split('-', -1)
          return false if (bounds.length > 2)

          bounds[0] = 0   if bounds[0].nil? or bounds[0].empty?
          bounds[1] = 255 if bounds[1].nil? or bounds[1].empty?
          bounds.map!{|b| b.to_i}
          return false if bounds[0] > bounds[1]
        else
          # Then it's a single value
          bounds[0] = r.to_i
        end
        return false if bounds[0] > 255 or (bounds[1] and bounds[1] > 255)
        return false if bounds[1] and bounds[0] > bounds[1]
        if bounds[1]
          bounds[0].upto(bounds[1]) do |i|
            sets.push(i)
          end
        elsif bounds[0]
          sets.push(bounds[0])
        end
      }
      bytes.push(sets.sort.uniq)
    }

    #
    # Combinitorically squish all of the quads together into a big list of
    # ip addresses, stored as ints
    #
    # e.g.:
    #  [[1],[1],[1,2],[1,2]]
    #  =>
    #  [atoi("1.1.1.1"),atoi("1.1.1.2"),atoi("1.1.2.1"),atoi("1.1.2.2")]
    addrs = []
    for a in bytes[0]
      for b in bytes[1]
        for c in bytes[2]
          for d in bytes[3]
            ip = (a << 24) + (b << 16) + (c << 8) + d
            addrs.push ip
          end
        end
      end
    end

    addrs.sort!
    addrs.uniq!

    rng = Range.new
    rng.options = { :ipv6 => false }
    rng.start = addrs[0]

    ranges = []
    1.upto(addrs.length - 1) do |idx|
      if addrs[idx - 1] + 1 == addrs[idx]
        # Then this address is contained in the current range
        next
      else
        # Then this address is the upper bound for the current range
        rng.stop = addrs[idx - 1]
        ranges.push(rng.dup)
        rng.start = addrs[idx]
      end
    end
    rng.stop = addrs[addrs.length - 1]
    ranges.push(rng.dup)
    return ranges
  end

end

# A range of IP addresses
class Range

  #@!attribute start
  #   The first address in this range, as a number
  #   @return [Fixnum]
  attr_accessor :start
  #@!attribute stop
  #   The last address in this range, as a number
  #   @return [Fixnum]
  attr_accessor :stop
  #@!attribute options
  #   @return [Hash]
  attr_accessor :options

  # @param start [Fixnum]
  # @param stop  [Fixnum]
  # @param options [Hash] Recognized keys are:
  #   * +:ipv6+
  #   * +:scope_id+
  def initialize(start=nil, stop=nil, options=nil)
    @start = start
    @stop = stop
    @options = options
  end

  # Compare attributes with +other+
  # @param other [Range]
  # @return [Boolean]
  def ==(other)
    (other.start == start && other.stop == stop && other.ipv6? == ipv6? && other.options == options)
  end

  # The number of addresses in this Range
  # @return [Fixnum]
  def length
    stop - start + 1
  end
  alias :count :length

  # Whether this Range contains IPv6 or IPv4 addresses
  # @return [Boolean]
  def ipv6?
    options[:ipv6]
  end
end

end
end
