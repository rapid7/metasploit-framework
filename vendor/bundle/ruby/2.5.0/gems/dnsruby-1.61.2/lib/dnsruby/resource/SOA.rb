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
    class SOA < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::SOA #:nodoc: all

      # The domain name of the original or primary nameserver for
      # this zone.
      attr_accessor :mname
      # A domain name that specifies the mailbox for the person
      # responsible for this zone.
      attr_accessor :rname
      # The zone's serial number.
      attr_accessor :serial
      # The zone's refresh interval.
      # How often, in seconds, a secondary nameserver is to check for
      # updates from the primary nameserver.
      attr_accessor :refresh
      # The zone's retry interval.
      # How often, in seconds, a secondary nameserver is to retry, after a
      # failure to check for a refresh
      attr_accessor :retry
      # The zone's expire interval.
      # How often, in seconds, a secondary nameserver is to use the data
      # before refreshing from the primary nameserver
      attr_accessor :expire
      # The minimum (default) TTL for records in this zone.
      attr_accessor :minimum

      def from_data(data) #:nodoc: all
        @mname, @rname, @serial, @refresh, @retry, @expire, @minimum = data
      end

      def from_hash(hash)
        @mname = Name.create(hash[:mname])
        @rname = Name.create(hash[:rname])
        @serial = hash[:serial].to_i
        @refresh = hash[:refresh].to_i
        @retry = hash[:retry].to_i
        @expire = hash[:expire].to_i
        @minimum = hash[:minimum].to_i
      end

      def from_string(input)
        if (input.length > 0)
          names = input.split(" ")
          @mname = Name.create(names[0])
          @rname = Name.create(names[1])
          @serial = names[2].to_i
          @refresh = names[3].to_i
          @retry = names[4].to_i
          @expire = names[5].to_i
          @minimum = names[6].to_i
        end
      end

      def rdata_to_string #:nodoc: all
        if (@mname!=nil)
          return "#{@mname.to_s(true)} #{@rname.to_s(true)} #{@serial} #{@refresh} #{@retry} #{@expire} #{@minimum}"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_name(@mname, canonical)
        msg.put_name(@rname, canonical)
        msg.put_pack('NNNNN', @serial, @refresh, @retry, @expire, @minimum)
      end

      def self.decode_rdata(msg) #:nodoc: all
        mname = msg.get_name
        rname = msg.get_name
        serial, refresh, retry_, expire, minimum = msg.get_unpack('NNNNN')
        return self.new(
                        [mname, rname, serial, refresh, retry_, expire, minimum])
      end
    end
  end
end