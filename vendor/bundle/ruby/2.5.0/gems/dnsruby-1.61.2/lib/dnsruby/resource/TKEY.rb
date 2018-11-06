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

  class Modes < CodeMapper
    #  The key is assigned by the server (unimplemented)
    SERVERASSIGNED		= 1

    #  The key is computed using a Diffie-Hellman key exchange
    DIFFIEHELLMAN		= 2

    #  The key is computed using GSS_API (unimplemented)
    GSSAPI			= 3

    #  The key is assigned by the resolver (unimplemented)
    RESOLVERASSIGNED	= 4

    #  The key should be deleted
    DELETE			= 5
    update()
  end

  class RR
    # RFC2930
    class TKEY < RR
      TypeValue = Types::TKEY #:nodoc: all
      ClassValue = nil #:nodoc: all
      ClassHash[[TypeValue, Classes::ANY]] = self #:nodoc: all

      attr_reader :key_size
      attr_accessor :key
      # Gets or sets the domain name that specifies the name of the algorithm.
      # The default algorithm is gss.microsoft.com
      # 
      #     rr.algorithm=(algorithm_name)
      #     print "algorithm = ", rr.algorithm, "\n"
      # 
      attr_accessor :algorithm
      # Gets or sets the inception time as the number of seconds since 1 Jan 1970
      # 00:00:00 UTC.
      # 
      # The default inception time is the current time.
      # 
      #     rr.inception=(time)
      #     print "inception = ", rr.inception, "\n"
      # 
      attr_accessor :inception
      # Gets or sets the expiration time as the number of seconds since 1 Jan 1970
      # 00:00:00 UTC.
      # 
      # The default expiration time is the current time plus 1 day.
      # 
      #     rr.expiration=(time)
      #     print "expiration = ", rr.expiration, "\n"
      # 
      attr_accessor :expiration
      # Sets the key mode (see rfc2930). The default is 3 which corresponds to GSSAPI
      # 
      #     rr.mode=(3)
      #     print "mode = ", rr.mode, "\n"
      # 
      attr_accessor :mode
      # Returns the RCODE covering TKEY processing.  See RFC 2930 for details.
      # 
      #     print "error = ", rr.error, "\n"
      # 
      attr_accessor :error
      # Returns the length of the Other Data.  Should be zero.
      # 
      #     print "other size = ", rr.other_size, "\n"
      # 
      attr_reader :other_size
      # Returns the Other Data.  This field should be empty.
      # 
      #     print "other data = ", rr.other_data, "\n"
      # 
      attr_reader :other_data

      def other_data=(od)
        @other_data=od
        @other_size=@other_data.length
      end

      def initialize
        @algorithm   = "gss.microsoft.com"
        @inception   = Time.now
        @expiration  = Time.now + 24*60*60
        @mode        = Modes.GSSAPI
        @error       = 0
        @other_size   = 0
        @other_data  = ""

        #  RFC 2845 Section 2.3
        @klass = Classes.ANY
        #  RFC 2845 Section 2.3
        @ttl = 0
      end

      def from_hash(hash)
        super(hash)
        if (algorithm)
        @algorithm = Name.create(hash[:algorithm])
        end
      end

      def from_data(data) #:nodoc: all
        @algorithm, @inception, @expiration, @mode, @error, @key_size, @key, @other_size, @other_data = data
      end

      #  Create the RR from a standard string
      def from_string(string) #:nodoc: all
        Dnsruby.log.error("Dnsruby::RR::TKEY#from_string called, but no text format defined for TKEY")
      end

      def rdata_to_string
        rdatastr=""

        if (@algorithm!=nil)
          error = @error
          error = "UNDEFINED" unless error!=nil
          rdatastr = "#{@algorithm.to_s(true)} #{error}"
          if (@other_size != nil && @other_size >0 && @other_data!=nil)
            rdatastr += " #{@other_data}"
          end
        end

        return rdatastr
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_name(@algorithm, canonical)
        msg.put_pack("NNnn", @inception, @expiration, @mode, @error)
        msg.put_pack("n", @key.length)
        msg.put_bytes(@key)
        msg.put_pack("n", @other_data.length)
        msg.put_bytes(@other_data)
      end

      def self.decode_rdata(msg) #:nodoc: all
        alg=msg.get_name
        inc, exp, mode, error  = msg.get_unpack("NNnn")
        key_size, =msg.get_unpack("n")
        key=msg.get_bytes(key_size)
        other_size, =msg.get_unpack("n")
        other=msg.get_bytes(other_size)
        return self.new([alg, inc, exp, mode, error, key_size, key, other_size, other])
      end
    end
  end
end