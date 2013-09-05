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
###
class RangeWalker

  #
  # Initializes a walker instance using the supplied range
  #
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
  def self.parse(parseme)
    self.new.parse(parseme)
  end

  #
  # Turn a human-readable range string into ranges we can step through one address at a time.
  #
  # Allow the following formats:
  #	"a.b.c.d e.f.g.h"
  #	"a.b.c.d, e.f.g.h"
  # where each chunk is CIDR notation, (e.g. '10.1.1.0/24') or a range in nmap format (see expand_nmap)
  #
  # OR this format
  #	"a.b.c.d-e.f.g.h"
  # where a.b.c.d and e.f.g.h are single IPs and the second must be
  # bigger than the first.
  #
  def parse(parseme)
    return nil if not parseme
    ranges = []
    parseme.split(', ').map{ |a| a.split(' ') }.flatten.each { |arg|
      opts = {}

      # Handle IPv6 first (support ranges, but not CIDR)
      if arg.include?(":")
        addrs = arg.split('-', 2)

        # Handle a single address
        if addrs.length == 1
          addr, scope_id = addrs[0].split('%')
          opts[:scope_id] = scope_id if scope_id

          return false unless Rex::Socket.is_ipv6?(addr)
          addr = Rex::Socket.addr_atoi(addr)
          ranges.push [addr, addr, true, opts]
          next
        end

        addr1, scope_id = addrs[0].split('%')
        opts[:scope_id] = scope_id if scope_id

        addr2, scope_id = addrs[0].split('%')
        ( opts[:scope_id] ||= scope_id ) if scope_id

        return false if not (Rex::Socket.is_ipv6?(addr1) and Rex::Socket.is_ipv6?(addr2))

        # Handle IPv6 ranges in the form of 2001::1-2001::10
        addr1 = Rex::Socket.addr_atoi(addr1)
        addr2 = Rex::Socket.addr_atoi(addr2)

        ranges.push [addr1, addr2, true, opts]
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
        Rex::Socket.addr_atoi_list(arg).each { |addr| ranges.push [addr, addr, false, opts] }

      # Handle IPv4 ranges
      elsif arg =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/
        # Then it's in the format of 1.2.3.4-5.6.7.8
        # Note, this will /not/ deal with DNS names, or the fancy/obscure 10...1-10...2
        begin
          addrs = [Rex::Socket.addr_atoi($1), Rex::Socket.addr_atoi($2)]
          return false if addrs[0] > addrs[1] # The end is greater than the beginning.
          ranges.push [addrs[0], addrs[1], false, opts]
        rescue Resolv::ResolvError # Something's broken, forget it.
          return false
        end
      else
        # Returns an array of ranges
        expanded = expand_nmap(arg)
        if expanded
          expanded.each { |r| ranges.push(r) }
        end
      end
    }

    # Remove any duplicate ranges
    ranges = ranges.uniq

    return ranges
  end

  #
  # Resets the subnet walker back to its original state.
  #
  def reset
    return false if not valid?
    @curr_range = 0
    @curr_addr = @ranges[0][0]
    @length = 0
    @ranges.each { |r| @length += r[1] - r[0] + 1 }
  end

  #
  # Returns the next IP address.
  #
  def next_ip
    return false if not valid?
    if (@curr_addr > @ranges[@curr_range][1])
      if (@curr_range >= @ranges.length - 1)
        return nil
      end
      @curr_range += 1
      @curr_addr = @ranges[@curr_range][0]
    end
    addr = Rex::Socket.addr_itoa(@curr_addr, @ranges[@curr_range][2])

    if @ranges[@curr_range][3][:scope_id]
      addr = addr + '%' + @ranges[@curr_range][3][:scope_id]
    end

    @curr_addr += 1
    return addr
  end

  def valid?
    (@ranges and not @ranges.empty?)
  end

  #
  # Returns true if the argument is an ip address that falls within any of
  # the stored ranges.
  #
  def include?(addr)
    return false if not @ranges
    if (addr.is_a? String)
      addr = Rex::Socket.addr_atoi(addr)
    end
    @ranges.map { |r|
      if r[0] <= addr and addr <= r[1]
        return true
      end
    }
    return false
  end

  #
  # Returns true if this RangeWalker includes all of the addresses in the
  # given RangeWalker
  #
  def include_range?(range_walker)
    return false if ((not @ranges) or @ranges.empty?)
    return false if not range_walker.ranges

    range_walker.ranges.all? do |start, stop|
      ranges.any? do |self_start, self_stop|
        r = (self_start..self_stop)
        r.include?(start) and r.include?(stop)
      end
    end
  end

  #
  # Calls the given block with each address. This is basically a wrapper for
  # #next_ip
  #
  def each(&block)
    while (ip = next_ip)
      block.call(ip)
    end
  end

  #
  # Returns an array with one element, a Range defined by the given CIDR
  # block.
  #
  def expand_cidr(arg)
    start,stop = Rex::Socket.cidr_crack(arg)
    if !start or !stop
      return false
    end
    range = Range.new
    range.start = Rex::Socket.addr_atoi(start)
    range.stop = Rex::Socket.addr_atoi(stop)
    range.ipv6 = (arg.include?(":"))
    range.options = {}

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
    rng.ipv6 = false
    rng.options = {}
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

  #
  # The total number of IPs within the range
  #
  attr_reader :length

  # for backwards compatibility
  alias :num_ips :length

  attr_reader :ranges

end

class Range < Array # :nodoc: all
  def start; self[0]; end
  def stop;  self[1]; end
  def ipv6;  self[2]; end
  def options; self[3]; end
  def start=(val); self[0] = val; end
  def stop=(val);  self[1] = val; end
  def ipv6=(val);  self[2] = val; end
  def options=(val); self[3] = val; end
end

end
end
