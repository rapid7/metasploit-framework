module Dnsruby

# RFC2181, section 5
# "It is however possible for most record types to exist
# with the same label, class and type, but with different data.  Such a
# group of records is hereby defined to be a Resource Record Set
# (RRSet)."
# This class also stores the RRSIG records which cover the RRSet
class RRSet
  include Comparable
  #  The number of RRSIGs stored in this RRSet
  attr_reader :num_sigs
  def initialize(rrs = [])
    if (!rrs.instance_of?Array)
      rrs = [rrs]
    end
    @rrs = []
    @num_sigs = 0
    rrs.each {|rr| add(rr)}
  end
  def self.new_from_string(string)
    rr_strings = string.split("\n")
    rrs = rr_strings.map { |s| Dnsruby::RR.new_from_string(s) }

    Dnsruby::RRSet.new(rrs)
  end    # The RRSIGs stored with this RRSet
  def sigs
    return @rrs[@rrs.length-@num_sigs, @num_sigs]
  end
  #  The RRs (not RRSIGs) stored in this RRSet
  def rrs
    return @rrs[0, @rrs.length-@num_sigs]
  end
  def privateAdd(r) #:nodoc:
    if @rrs.include?r
      return true
    end
    new_pos = @rrs.length - @num_sigs
    if ((@num_sigs == @rrs.length)  && @num_sigs > 0) # if we added RRSIG first
      if (((r.type != @rrs.last.type_covered) && (r.type != Types.RRSIG))||
          ((r.type == Types.RRSIG) && (r.type_covered != @rrs.last.type_covered)))
        return false
      end
    end
    if (r.type == Types::RRSIG)
      new_pos = @rrs.length
      @num_sigs += 1
    end
    @rrs.insert(new_pos, r)
    return true
  end

  # Add the RR to this RRSet
  # Takes a copy of the RR by default. To suppress this, pass false
  # as the second parameter.
  def add(rin, do_clone = true)
    if (rin.instance_of?RRSet)
      ret = false
      [rin.rrs, rin.sigs].each {|rr| ret = add(rr)}
      return ret
    end
    #       r = RR.create(r.to_s) # clone the record
    r = nil
    if do_clone
      r = rin.clone
    else
      r = rin
    end
    if (@rrs.size() == 0) #  && !(r.type == Types.RRSIG))
      return privateAdd(r)
    end
    #  Check the type, klass and ttl are correct
    first = @rrs[0]
    if (!r.sameRRset(first))
      return false
      #         raise ArgumentError.new("record does not match rrset")
    end

    if (!(r.type == Types::RRSIG) && (!(first.type == Types::RRSIG)))
      if (r.ttl != first.ttl) # RFC2181, section 5.2
        if (r.ttl > first.ttl)
          r.ttl=(first.ttl)
        else
          @rrs.each do |rr|
            rr.ttl = r.ttl
          end
        end
      end
    end

    return privateAdd(r)
    #       return true
  end

  def <=>(other)
    #       return 1 if ((!other) || !(other.name) || !(other.type))
    #       return -1 if (!@name)
    if (name.canonical == other.name.canonical)
      return type.code <=> other.type.code
    else
      return name <=> other.name
    end
  end

  def sort_canonical
    # Make a list, for all the RRs, where each RR contributes
    # the canonical RDATA encoding
    canonical_rrs = {}
    self.rrs.each do |rr|
      data = MessageEncoder.new {|msg|
        rr.encode_rdata(msg, true)
      }.to_s
      canonical_rrs[data] = rr
    end

    return_rrs = RRSet.new
    canonical_rrs.keys.sort.each { |rdata|
      return_rrs.add(canonical_rrs[rdata], false)
    }
    return return_rrs
  end

  def ==(other)
    return false unless other.instance_of?RRSet
    return false if (other.sigs.length != self.sigs.length)
    return false if (other.rrs.length != self.rrs.length)
    return false if (other.ttl != self.ttl)
    otherrrs = other.rrs
    self.rrs.each {|rr|
      return false if (!otherrrs.include?rr)
    }
    othersigs= other.sigs
    self.sigs.each {|sig|
      return false if (!othersigs.include?sig)
    }
    return true
  end
  # Delete the RR from this RRSet
  def delete(rr)
    @rrs.delete(rr)
  end
  def each
    @rrs.each do |rr|
      yield rr
    end
  end
  def [](index)
    return @rrs[index]
  end
  # Return the type of this RRSet
  def type
    if (@rrs[0])
      return @rrs[0].type
    end
    return nil
  end
  # Return the klass of this RRSet
  def klass
    return @rrs[0].klass
  end
  # Return the ttl of this RRSet
  def ttl
    return @rrs[0].ttl
  end
  def ttl=(ttl)
    [rrs, sigs].each {|rrs|
      rrs.each {|rr|
        rr.ttl = ttl
      }
    }
  end
  def name
    if (@rrs[0])
      return @rrs[0].name
    else
      return nil
    end
  end
  def to_s
    ret = ""
    each {|rec|
      ret += rec.to_s + "\n"
    }
    return ret
  end
  def length
    return @rrs.length
  end
end
end
