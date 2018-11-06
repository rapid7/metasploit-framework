module Dnsruby
class Section < Array

  def initialize(msg = nil)
    @msg = msg
    super(0)
  end

  #  Return the rrset of the specified type in this section
  def rrset(name, type=Types.A, klass=Classes::IN)
    rrs = select{|rr|
      type_ok = (rr.type==type)
      if rr.type == Types::RRSIG
        type_ok = (rr.type_covered == type)
      end
      unless /\.\z/ =~ name.to_s
        name = name.to_s + '.'
      end
      type_ok && (rr.klass == klass) && (rr.name.to_s(true).downcase == name.to_s().downcase)
    }
    rrset = RRSet.new()
    rrs.each do |rr|
      rrset.add(rr)
    end
    rrset
  end

  #  Return an array of all the rrsets in the section
  def rrsets(type = nil, include_opt = false)
    if type && !(Types === type)
      type = Types.new(type)
    end
    ret = []
    each do |rr|
      next if (!include_opt && (rr.type == Types::OPT))
      #           if (type)
      #             next if ((rr.type == Types.RRSIG) && (type != Types.RRSIG) && (rr.type_covered != type))
      #             next if (rr.type != type)
      #           end
      if (type)
        #  if this is an rrsig type, then :
        #     only include it if the type_covered is the type requested,
        #     OR if the type requested is an RRSIG
        if rr.type == Types::RRSIG
          if (rr.type_covered == type) || (type == Types::RRSIG)
          else
            next
          end
          #               next if ((rr.type_covered != type) || (type != Types.RRSIG))
        elsif rr.type != type
          next
        end
      end

      found_rrset = false
      ret.each do |rrset|
        found_rrset = rrset.add(rr)
        break if found_rrset
      end
      unless found_rrset
        ret.push(RRSet.new(rr))
      end
    end
    ret
  end

  def ==(other)
    return false unless self.class == other.class
    return false if other.rrsets(nil, true).length != self.rrsets(nil, true).length

    otherrrsets = other.rrsets(nil)
    self.rrsets(nil).each {|rrset|
      return false unless otherrrsets.include?(rrset)
    }

    true
  end

  def remove_rrset(name, type)
    #  Remove all RRs with the name and type from the section.
    #  Need to worry about header counts here - can we get Message to
    #  update the counts itself, rather than the section worrying about it?
    rrs_to_delete = []
    each do |rr|
      next if rr.rr_type == Types::OPT
      if (rr.name.to_s.downcase == name.to_s.downcase) &&
          ((rr.type == type) ||
              ((rr.type == Types::RRSIG) && (rr.type_covered == type)))
        rrs_to_delete.push(rr)
      end
    end
    rrs_to_delete.each { |rr| delete(rr) }
    @msg.update_counts if @msg
  end
end
end
