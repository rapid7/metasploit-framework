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
# require 'base64'
begin
require 'openssl'
rescue LoadError
  print "OpenSSL not found - ignoring\n"
end
module Dnsruby
  class RR
    # TSIG implements RFC2845.
    # 
    # "This protocol allows for transaction level authentication using
    # shared secrets and one way hashing.  It can be used to authenticate
    # dynamic updates as coming from an approved client, or to authenticate
    # responses as coming from an approved recursive name server."
    # 
    # A Dnsruby::RR::TSIG can represent the data present in a TSIG RR.
    # However, it can also represent the data (specified in RFC2845) used
    # to sign or verify a DNS message.
    # 
    # 
    # Example code :
    #     res = Dnsruby::Resolver.new("ns0.validation-test-servers.nominet.org.uk")
    # 
    #     # Now configure the resolver with the TSIG key for signing/verifying
    #     KEY_NAME="rubytsig"
    #     KEY = "8n6gugn4aJ7MazyNlMccGKH1WxD2B3UvN/O/RA6iBupO2/03u9CTa3Ewz3gBWTSBCH3crY4Kk+tigNdeJBAvrw=="
    #     res.tsig=KEY_NAME, KEY
    # 
    #     update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    #     # Generate update record name, and test it has been made. Then delete it and check it has been deleted
    #     update_name = generate_update_name
    #     update.absent(update_name)
    #     update.add(update_name, 'TXT', 100, "test signed update")
    # 
    #     # Resolver will automatically sign message and verify response
    #     response = res.send_message(update)
    #     assert(response.verified?) # Check that the response has been verified
    class TSIG < RR
      HMAC_MD5 = Name.create("HMAC-MD5.SIG-ALG.REG.INT.")
      HMAC_SHA1 = Name.create("hmac-sha1.")
      HMAC_SHA256 = Name.create("hmac-sha256.")
      HMAC_SHA512 = Name.create("hmac-sha512.")

      DEFAULT_FUDGE     = 300

      DEFAULT_ALGORITHM = HMAC_MD5

      # Generates a TSIG record and adds it to the message.
      # Takes an optional original_request argument for the case where this is
      # a response to a query (RFC2845 3.4.1)
      # 
      # Message#tsigstate will be set to :Signed.
      def apply(message, original_request=nil)
        if (!message.signed?)
          tsig_rr = generate(message, original_request)
          message.add_additional(tsig_rr)
          message.tsigstate = :Signed
          @query = message
          tsig_rr.query = message
        end
      end

      def query=q#:nodoc: all
        @query = q
      end


      # Generates a TSIG record
      def generate(msg, original_request = nil, data="", msg_bytes=nil, tsig_rr=self)#:nodoc: all
        time_signed=@time_signed
        if (!time_signed)
          time_signed=Time.now.to_i
        end
        if (tsig_rr.time_signed)
          time_signed = tsig_rr.time_signed
        end

        if (original_request)
          # 	# Add the request MAC if present (used to validate responses).
          # 	  hmac.update(pack("H*", request_mac))
          mac_bytes = MessageEncoder.new {|m|
            m.put_pack('n', original_request.tsig.mac_size)
            m.put_bytes(original_request.tsig.mac)
          }.to_s
          data  += mac_bytes
          #  Original ID - should we set message ID to original ID?
          if (tsig_rr != self)
            msg.header.id = tsig_rr.original_id
          else
            msg.header.id = original_request.header.id
          end
        end

        if (!msg_bytes)
          msg_bytes = msg.encode
          data += msg_bytes
        else
          #  If msg_bytes came in, we need somehow to remove the TSIG RR
          #  It is the last record, so we can strip it if we know where it starts
          #  We must also poke the header ARcount to decrement it
          msg_bytes = Header.decrement_arcount_encoded(msg_bytes)
          data += msg_bytes[0, msg.tsigstart]
        end

        data += sig_data(tsig_rr, time_signed)

        mac = calculate_mac(tsig_rr.algorithm, data)

        mac_size = mac.length

        new_tsig_rr = Dnsruby::RR.create({
            :name        => tsig_rr.name,
            :type        => Types.TSIG,
            :ttl         => tsig_rr.ttl,
            :klass       => tsig_rr.klass,
            :algorithm   => tsig_rr.algorithm,
            :fudge       => tsig_rr.fudge,
            :key         => @key,
            :mac         => mac,
            :mac_size    => mac_size,
            :error       => tsig_rr.error,
            :time_signed => time_signed,
            :original_id => msg.header.id
          })
        return new_tsig_rr

      end

      def calculate_mac(algorithm, data)
        mac=nil
# + if (key_size > max_digest_len) {
# +   EVP_DigestInit(&ectx, digester);
# +   EVP_DigestUpdate(&ectx, (const void*) key_bytes, key_size);
# +   EVP_DigestFinal(&ectx, key_bytes, NULL);
# +   key_size = max_digest_len;
# + }
        key = @key.gsub(" ", "")
 #        key = Base64::decode64(key)
        key = key.unpack("m*")[0]
        if (algorithm.to_s.downcase == HMAC_MD5.to_s.downcase)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, data)
        elsif (algorithm == HMAC_SHA1)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, key, data)
        elsif (algorithm == HMAC_SHA256)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, key, data)
        elsif (algorithm == HMAC_SHA512)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA512.new, key, data)
        else
          #  Should we allow client to pass in their own signing function?
          raise VerifyError.new("Algorithm #{algorithm} unsupported by TSIG")
        end
        return mac
      end

      #  Private method to return the TSIG RR data to be signed
      def sig_data(tsig_rr, time_signed=@time_signed) #:nodoc: all
        return MessageEncoder.new { |msg|
          msg.put_name(tsig_rr.name.downcase, true)
          msg.put_pack('nN', tsig_rr.klass.code, tsig_rr.ttl)
          msg.put_name(tsig_rr.algorithm.downcase, true)

          time_high = (time_signed >> 32)
          time_low = (time_signed & 0xFFFFFFFF)
          msg.put_pack('nN', time_high, time_low)
          msg.put_pack('n', tsig_rr.fudge)
          msg.put_pack('n', tsig_rr.error)
          msg.put_pack('n', tsig_rr.other_size)
          msg.put_bytes(tsig_rr.other_data)
        }.to_s
      end

      # Verify a response. This method will be called by Dnsruby::SingleResolver
      # before passing a response to the client code.
      # The TSIG record will be removed from packet before passing to client, and
      # the Message#tsigstate and Message#tsigerror will be set accordingly.
      # Message#tsigstate will be set to one of :
      # *  :Failed
      # *  :Verified
      def verify(query, response, response_bytes, buf="")
        #         4.6. Client processing of answer
        # 
        #    When a client receives a response from a server and expects to see a
        #    TSIG, it first checks if the TSIG RR is present in the response.
        #    Otherwise, the response is treated as having a format error and
        #    discarded.  The client then extracts the TSIG, adjusts the ARCOUNT,
        #    and calculates the keyed digest in the same way as the server.  If
        #    the TSIG does not validate, that response MUST be discarded, unless
        #    the RCODE is 9 (NOTAUTH), in which case the client SHOULD attempt to
        #    verify the response as if it were a TSIG Error response, as specified
        #    in [4.3].  A message containing an unsigned TSIG record or a TSIG
        #    record which fails verification SHOULD not be considered an
        #    acceptable response; the client SHOULD log an error and continue to
        #    wait for a signed response until the request times out.

        #  So, this verify method should simply remove the TSIG RR and calculate
        #  the MAC (using original request MAC if required).
        #  Should set tsigstate on packet appropriately, and return error.
        #  Side effect is packet is stripped of TSIG.
        #  Resolver (or client) can then decide what to do...

        msg_tsig_rr = response.tsig
        if (!verify_common(response))
          return false
        end

        new_msg_tsig_rr = generate(response, query, buf, response_bytes, msg_tsig_rr)

        if (msg_tsig_rr.mac == new_msg_tsig_rr.mac)
          response.tsigstate = :Verified
          response.tsigerror = RCode.NOERROR
          return true
        else
          response.tsigstate = :Failed
          response.tsigerror = RCode.BADSIG
          return false
        end
      end

      def verify_common(response)#:nodoc: all
        tsig_rr = response.tsig

	if (!tsig_rr)
          response.tsigerror = RCode.FORMERR
          response.tsigstate = :Failed
          return false
        end

        response.additional.delete(tsig_rr)
        response.header.arcount-=1

        #  First, check the TSIG error in the RR
        if (tsig_rr.error != RCode.NOERROR)
          response.tsigstate = :Failed
          response.tsigerror = tsig_rr.error
          return false
        end

	if ((tsig_rr.name != @name) || (tsig_rr.algorithm.downcase != @algorithm.downcase))
          Dnsruby.log.error("BADKEY failure")
          response.tsigstate = :Failed
          response.tsigerror = RCode.BADKEY
          return false
        end

        #  Check time_signed (RFC2845, 4.5.2) - only really necessary for server
        if (Time.now.to_i > tsig_rr.time_signed + tsig_rr.fudge  ||
              Time.now.to_i < tsig_rr.time_signed - tsig_rr.fudge)
          Dnsruby.log.error("TSIG failed with BADTIME")
          response.tsigstate = :Failed
          response.tsigerror = RCode.BADTIME
          return false
        end

        return true
      end

      # Checks TSIG signatures across sessions of multiple DNS envelopes.
      # This method is called each time a new envelope comes in. The envelope
      # is checked - if a TSIG is present, them the stream so far is verified,
      # and the response#tsigstate set to :Verified. If a TSIG is not present,
      # and does not need to be present, then the message is added to the digest
      # stream and the response#tsigstate is set to :Intermediate.
      # If there is an error with the TSIG verification, then the response#tsigstate
      # is set to :Failed.
      # Like verify, this method will only be called by the Dnsruby::SingleResolver
      # class. Client code need not call this method directly.
      def verify_envelope(response, response_bytes)
        # RFC2845 Section 4.4
        # -----
        # A DNS TCP session can include multiple DNS envelopes.  This is, for
        # example, commonly used by zone transfer.  Using TSIG on such a
        # connection can protect the connection from hijacking and provide data
        # integrity.  The TSIG MUST be included on the first and last DNS
        # envelopes.  It can be optionally placed on any intermediary
        # envelopes.  It is expensive to include it on every envelopes, but it
        # MUST be placed on at least every 100'th envelope.  The first envelope
        # is processed as a standard answer, and subsequent messages have the
        # following digest components:
        # 
        # *   Prior Digest (running)
        # *   DNS Messages (any unsigned messages since the last TSIG)
        # *   TSIG Timers (current message)
        # 
        # This allows the client to rapidly detect when the session has been
        # altered; at which point it can close the connection and retry.  If a
        # client TSIG verification fails, the client MUST close the connection.
        # If the client does not receive TSIG records frequently enough (as
        # specified above) it SHOULD assume the connection has been hijacked
        # and it SHOULD close the connection.  The client SHOULD treat this the
        # same way as they would any other interrupted transfer (although the
        # exact behavior is not specified).
        # -----
        # 
        #  Each time a new envelope comes in, this method is called on the QUERY TSIG RR.
        #  It will set the response tsigstate to :Verified :Intermediate or :Failed
        #  as appropriate.

        #  Keep digest going of messages as they come in (and mark them intermediate)
        #  When TSIG comes in, work out what key should be and check. If OK, mark
        #  verified. Can reset digest then.
        if (!@buf)
          @num_envelopes = 0
          @last_signed = 0
        end
        @num_envelopes += 1
        if (!response.tsig)
          if ((@num_envelopes > 1) && (@num_envelopes - @last_signed < 100))
            Dnsruby.log.debug("Receiving intermediate envelope in TSIG TCP session")
            response.tsigstate = :Intermediate
            response.tsigerror = RCode.NOERROR
            @buf = @buf + response_bytes
            return
          else
            response.tsigstate = :Failed
            Dnsruby.log.error("Expecting signed packet")
            return false
          end
        end
        @last_signed = @num_envelopes

        #  We have a TSIG - process it!
        tsig = response.tsig
        if (@num_envelopes == 1)
          Dnsruby.log.debug("First response in TSIG TCP session - verifying normally")
          #  Process it as a standard answer
          ok = verify(@query, response, response_bytes)
          if (ok)
            mac_bytes = MessageEncoder.new {|m|
              m.put_pack('n', tsig.mac_size)
              m.put_bytes(tsig.mac)
            }.to_s
            @buf = mac_bytes
          end
          return ok
        end
        Dnsruby.log.debug("Processing TSIG on TSIG TCP session")

        if (!verify_common(response))
          return false
        end

        #  Now add the current message data - remember to frig the arcount
        response_bytes = Header.decrement_arcount_encoded(response_bytes)
        @buf += response_bytes[0, response.tsigstart]

        #  Let's add the timers
        timers_data = MessageEncoder.new { |msg|
          time_high = (tsig.time_signed >> 32)
          time_low = (tsig.time_signed & 0xFFFFFFFF)
          msg.put_pack('nN', time_high, time_low)
          msg.put_pack('n', tsig.fudge)
        }.to_s
        @buf += timers_data

        mac = calculate_mac(tsig.algorithm, @buf)

        if (mac != tsig.mac)
          Dnsruby.log.error("TSIG Verify error on TSIG TCP session")
          response.tsigstate = :Failed
          return false
        end
        mac_bytes = MessageEncoder.new {|m|
          m.put_pack('n', mac.length)
          m.put_bytes(mac)
        }.to_s
        @buf=mac_bytes

        response.tsigstate = :Verified
        response.tsigerror = RCode.NOERROR
        return true
      end


      TypeValue = Types::TSIG #:nodoc: all
      ClassValue = nil #:nodoc: all
      ClassHash[[TypeValue, Classes::ANY]] = self #:nodoc: all

      # Gets or sets the domain name that specifies the name of the algorithm.
      # The only algorithms currently supported are hmac-md5 and hmac-sha1.
      # 
      #     rr.algorithm=(algorithm_name)
      #     print "algorithm = ", rr.algorithm, "\n"
      # 
      attr_reader :algorithm

      # Gets or sets the signing time as the number of seconds since 1 Jan 1970
      # 00:00:00 UTC.
      # 
      # The default signing time is the current time.
      # 
      #     rr.time_signed=(time)
      #     print "time signed = ", rr.time_signed, "\n"
      # 
      attr_accessor :time_signed

      # Gets or sets the "fudge", i.e., the seconds of error permitted in the
      # signing time.
      # 
      # The default fudge is 300 seconds.
      # 
      #     rr.fudge=(60)
      #     print "fudge = ", rr.fudge, "\n"
      # 
      attr_reader :fudge

      # Returns the number of octets in the message authentication code (MAC).
      # The programmer must call a Net::DNS::Packet object's data method
      # before this will return anything meaningful.
      # 
      #     print "MAC size = ", rr.mac_size, "\n"
      # 
      attr_accessor :mac_size

      # Returns the message authentication code (MAC) as a string of hex
      # characters.  The programmer must call a Net::DNS::Packet object's
      # data method before this will return anything meaningful.
      # 
      #     print "MAC = ", rr.mac, "\n"
      # 
      attr_accessor :mac

      # Gets or sets the original message ID.
      # 
      #     rr.original_id(12345)
      #     print "original ID = ", rr.original_id, "\n"
      # 
      attr_accessor :original_id

      # Returns the RCODE covering TSIG processing.  Common values are
      # NOERROR, BADSIG, BADKEY, and BADTIME.  See RFC 2845 for details.
      # 
      #     print "error = ", rr.error, "\n"
      # 
      attr_accessor :error

      # Returns the length of the Other Data.  Should be zero unless the
      # error is BADTIME.
      # 
      #     print "other len = ", rr.other_size, "\n"
      # 
      attr_accessor :other_size

      # Returns the Other Data.  This field should be empty unless the
      # error is BADTIME, in which case it will contain the server's
      # time as the number of seconds since 1 Jan 1970 00:00:00 UTC.
      # 
      #     print "other data = ", rr.other_data, "\n"
      # 
      attr_accessor :other_data

      # Stores the secret key used for signing/verifying messages.
      attr_accessor :key

      def init_defaults
        #  @TODO@ Have new() method which takes key_name and key?
        @algorithm   = DEFAULT_ALGORITHM
        @fudge       = DEFAULT_FUDGE
        @mac_size    = 0
        @mac         = ""
        @original_id = rand(65536)
        @error       = 0
        @other_size   = 0
        @other_data  = ""
        @time_signed = nil
        @buf = nil

        #  RFC 2845 Section 2.3
        @klass = Classes.ANY

        @ttl = 0 # RFC 2845 Section 2.3
      end

      def from_data(data) #:nodoc: all
        @algorithm, @time_signed, @fudge, @mac_size, @mac, @original_id, @error, @other_size, @other_data = data
      end

      def name=(n)
        if (n.instance_of?String)
          n = Name.create(n)
        end
        if (!n.absolute?)
          @name = Name.create(n.to_s + ".")
        else
          @name = n
        end
      end

      #  Create the RR from a standard string
      def from_string(str) #:nodoc: all
        parts = str.split("[:/]")
        if (parts.length < 2 || parts.length > 3)
          raise ArgumentException.new("Invalid TSIG key specification")
        end
        if (parts.length == 3)
          return TSIG.new(parts[0], parts[1], parts[2]);
        else
          return TSIG.new(HMAC_MD5, parts[0], parts[1]);
        end
      end

      # Set the algorithm to use to generate the HMAC
      # Supported values are :
      # * hmac-md5
      # * hmac-sha1
      # * hmac-sha256
      # * hmac-sha512
      def algorithm=(alg)
        if (alg.class == String)
          if (alg.downcase=="hmac-md5")
            @algorithm = HMAC_MD5;
          elsif (alg.downcase=="hmac-sha1")
            @algorithm = HMAC_SHA1;
          elsif (alg.downcase=="hmac-sha256")
            @algorithm = HMAC_SHA256;
          elsif (alg.downcase=="hmac-sha512")
            @algorithm = HMAC_SHA512;
          else
            raise ArgumentError.new("Invalid TSIG algorithm")
          end
        elsif (alg.class == Name)
          if (alg!=HMAC_MD5 && alg!=HMAC_SHA1 && alg!=HMAC_SHA256 && alg!=HMAC_SHA512)
            raise ArgumentException.new("Invalid TSIG algorithm")
          end
          @algorithm=alg
        else
          raise ArgumentError.new("#{alg.class} not valid type for Dnsruby::RR::TSIG#algorithm=  - use String or Name")
        end
        Dnsruby.log.debug{"Using #{@algorithm.to_s} algorithm"}
      end

      def fudge=(f)
        if (f < 0 || f > 0x7FFF)
          @fudge = DEFAULT_FUDGE
        else
          @fudge = f
        end
      end

      def rdata_to_string
        rdatastr=""
        if (@algorithm!=nil)
          error = @error
          error = "UNDEFINED" unless error!=nil
          rdatastr = "#{@original_id} #{@time_signed} #{@algorithm.to_s(true)} #{error}";
          if (@other_size > 0 && @other_data!=nil)
            rdatastr += " #{@other_data}"
          end
          rdatastr += " " + mac.unpack("H*").to_s
        end

        return rdatastr
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        #  Name needs to be added with no compression - done in Dnsruby::Message#encode
        msg.put_name(@algorithm.downcase, true)
        time_high = (@time_signed >> 32)
        time_low = (@time_signed & 0xFFFFFFFF)
        msg.put_pack('nN', time_high, time_low)
        msg.put_pack('n', @fudge)
        msg.put_pack('n', @mac_size)
        msg.put_bytes(@mac)
        msg.put_pack('n', @original_id)
        msg.put_pack('n', @error)
        msg.put_pack('n', @other_size)
        msg.put_bytes(@other_data)
      end

      def self.decode_rdata(msg) #:nodoc: all
        alg=msg.get_name
        time_high, time_low = msg.get_unpack("nN")
        time_signed = (time_high << 32) + time_low
        fudge, = msg.get_unpack("n")
        mac_size, = msg.get_unpack("n")
        mac = msg.get_bytes(mac_size)
        original_id, = msg.get_unpack("n")
        error, = msg.get_unpack("n")
        other_size, = msg.get_unpack("n")
        other_data = msg.get_bytes(other_size)
        return self.new([alg, time_signed, fudge, mac_size, mac, original_id, error, other_size, other_data])
      end
    end
  end
end
