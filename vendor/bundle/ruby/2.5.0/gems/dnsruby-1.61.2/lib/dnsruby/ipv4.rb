# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  class IPv4
    #  Regular expression IPv4 addresses must match
    Regex = /\A(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\z/

    def self.create(arg)
      case arg
      when IPv4
        return arg
      when Regex
        if (0..255) === (a = $1.to_i) &&
         (0..255) === (b = $2.to_i) &&
         (0..255) === (c = $3.to_i) &&
         (0..255) === (d = $4.to_i)
          return self.new([a, b, c, d].pack("CCCC"))
        else
          raise ArgumentError.new("IPv4 address with invalid value: " + arg)
        end
      else
        raise ArgumentError.new("cannot interpret as IPv4 address: #{arg.inspect}")
      end
    end

    def initialize(address) #:nodoc:
      unless address.kind_of?(String) && address.length == 4
        raise ArgumentError.new('IPv4 address must be 4 bytes')
      end
      @address = address
    end

    #  A String representation of the IPv4 address.
    attr_reader :address

    def to_s #:nodoc:
      return sprintf("%d.%d.%d.%d", *@address.unpack("CCCC"))
    end

    def inspect #:nodoc:
      return "#<#{self.class} #{self.to_s}>"
    end

    def to_name
      return Name.create(
        '%d.%d.%d.%d.in-addr.arpa.' % @address.unpack('CCCC').reverse)
    end

    def ==(other)
      return @address == other.address
    end

    def eql?(other)
      return self == other
    end

    def hash
      return @address.hash
    end
  end
end
