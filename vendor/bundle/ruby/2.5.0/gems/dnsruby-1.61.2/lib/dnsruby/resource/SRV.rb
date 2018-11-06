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
  class RR
    module IN
      #  SRV resource record defined in RFC 2782
      # 
      #  These records identify the hostname and port that a service is
      #  available at.
      # 
      #  The format is:
      #    _Service._Proto.Name TTL Class SRV Priority Weight Port Target
      # 
      #  The fields specific to SRV are defined in RFC 2782
      class SRV < RR
        ClassHash[[TypeValue = Types::SRV, ClassValue = ClassValue]] = self #:nodoc: all

        #  The priority of this target host.
        #  A client MUST attempt
        #  to contact the target host with the lowest-numbered priority it can
        #  reach; target hosts with the same priority SHOULD be tried in an
        #  order defined by the weight field.  The range is 0-65535.  Note that
        #  it is not widely implemented and should be set to zero.
        attr_accessor :priority

        #  A server selection mechanism.
        #  The weight field specifies
        #  a relative weight for entries with the same priority. Larger weights
        #  SHOULD be given a proportionately higher probability of being
        #  selected. The range of this number is 0-65535.  Domain administrators
        #  SHOULD use Weight 0 when there isn't any server selection to do, to
        #  make the RR easier to read for humans (less noisy). Note that it is
        #  not widely implemented and should be set to zero.
        attr_accessor :weight

        #  The port on this target host of this service.  The range is 0-65535.
        attr_accessor :port

        #  The domain name of the target host. A target of "." means
        #  that the service is decidedly not available at this domain.
        attr_accessor :target

        def from_data(data) #:nodoc: all
          @priority, @weight, @port, @target = data
        end

        def from_hash(hash)
          if hash[:priority]
            @priority = hash[:priority].to_i
          end
          if hash[:weight]
            @weight = hash[:weight].to_i
          end
          if hash[:port]
            @port = hash[:port].to_i
          end
          if hash[:target]
            @target= Name.create(hash[:target])
          end
        end

        def from_string(input)
          if (input.length > 0)
            names = input.split(" ")
            @priority = names[0].to_i
            @weight = names[1].to_i
            @port = names[2].to_i
            if (names[3])
              @target = Name.create(names[3])
            end
          end
        end

        def rdata_to_string
          if (@target!=nil)
            return "#{@priority} #{@weight} #{@port} #{@target.to_s(true)}"
          else
            return ""
          end
        end

        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_pack("n", @priority)
          msg.put_pack("n", @weight)
          msg.put_pack("n", @port)
          msg.put_name(@target,canonical)
        end

        def self.decode_rdata(msg) #:nodoc: all
          priority, = msg.get_unpack("n")
          weight,   = msg.get_unpack("n")
          port,     = msg.get_unpack("n")
          target    = msg.get_name
          return self.new([priority, weight, port, target])
        end
      end
    end
  end
end