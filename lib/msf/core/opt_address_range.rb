# -*- coding: binary -*-

module Msf

###
#
# Network address range option.
#
###
class OptAddressRange < OptBase
  def type
    return 'addressrange'
  end

  def validate_on_assignment?
    false
  end

  def normalize(value)
    return nil unless value.kind_of?(String)
    # accept both "file://<path>" and "file:<path>" syntax
    if (value =~ /^file:\/\/(.*)/) || (value =~ /^file:(.*)/)
      path = $1
      return false if not File.exist?(path) or File.directory?(path)
      return File.readlines(path).map{ |s| s.strip}.join(" ")
    elsif (value =~ /^rand:(.*)/)
      count = $1.to_i
      return false if count < 1
      ret = ''
      count.times {
        ret << " " if not ret.empty?
        ret << [ rand(0x100000000) ].pack("N").unpack("C*").map{|x| x.to_s }.join(".")
      }
      return ret
    end
    return value
  end

  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) or value.kind_of?(NilClass)

    if (value != nil and value.empty? == false)
      normalized = normalize(value)
      return false if normalized.nil?
      walker = Rex::Socket::RangeWalker.new(normalized)
      if (not walker or not walker.valid?)
        return false
      end
    end

    return super
  end
end

end
