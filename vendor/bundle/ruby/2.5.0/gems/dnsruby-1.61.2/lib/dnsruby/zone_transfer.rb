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
  #  This class performs zone transfers as per RFC1034 (AXFR) and RFC1995 (IXFR).
  class ZoneTransfer
    #  The nameserver to use for the zone transfer - defaults to system config
    attr_accessor :server
    #  What type of transfer to do (IXFR or AXFR) - defaults to AXFR
    attr_accessor :transfer_type
    #  The class - defaults to IN
    attr_accessor :klass
    #  The port to connect to - defaults to 53
    attr_accessor :port
    #  If using IXFR, this is the SOA serial number to start the incrementals from
    attr_accessor :serial
    #  The source address to connect to
    attr_accessor :src_address
    #  The TSIG record used to sign the transfer
    attr_reader :tsig
    #  Returns the tsigstate of the last transfer (nil if no TSIG signed transfer has occurred)
    attr_reader :last_tsigstate
    # Sets the connect timeout in seconds
    attr_accessor :connect_timeout

    # Sets the TSIG to sign the zone transfer with.
    # Pass in either a Dnsruby::RR::TSIG, or a key_name and key (or just a key)
    # Pass in nil to stop tsig signing.
    # * res.tsig=(tsig_rr)
    # * res.tsig=(key_name, key)
    # * res.tsig=nil # Don't sign the transfer
    def tsig=(*args)
      @tsig = Resolver.get_tsig(args)
    end


    def initialize
      @server=Config.new.nameserver[0]
      @transfer_type = Types.AXFR
      @klass=Classes.IN
      @port=53
      @serial=0
      @tsig = nil
      @axfr = nil
      @src_address = nil
      @connect_timeout = 5
    end

    #  Perform a zone transfer (RFC1995)
    #  If an IXFR query is unsuccessful, then AXFR is tried (and @transfer_type is set
    #  to AXFR)
    #  TCP is used as the only transport
    # 
    #  If AXFR is performed, then the zone will be returned as a set of records :
    # 
    #        zt = Dnsruby::ZoneTransfer.new
    #        zt.transfer_type = Dnsruby::Types.AXFR
    #        zt.server = "ns0.validation-test-servers.nominet.org.uk"
    #        zone = zt.transfer("validation-test-servers.nominet.org.uk")
    #        soa = zone[0]
    #        rec1 = zone[1]
    #        print zone.to_s
    # 
    # 
    #  If IXFR is performed, then the incrementals will be returned as a set of Deltas.
    #  Each Delta contains the start and end SOA serial number, as well as an array of
    #  adds and deletes that occurred between the start and end.
    # 
    #         zt = Dnsruby::ZoneTransfer.new
    #         zt.transfer_type = Dnsruby::Types.IXFR
    #         zt.server = "ns0.validation-test-servers.nominet.org.uk"
    #         zt.serial = 2007090401
    #         deltas = zt.transfer("validation-test-servers.nominet.org.uk")
    #         assert_equal("Should show up in transfer", deltas[0].adds[1].data)
    def transfer(zone)
      servers = @server
      if (servers.class == String)
        servers=[servers]
      end
      xfr = nil
      exception = nil
      servers.each do |server|
        begin
          server=Config.resolve_server(server)
          xfr = do_transfer(zone, server)
          break
        rescue Exception => e
          exception = e
        end
      end
      if (xfr == nil && exception != nil)
        raise exception
      end
      return xfr
    end

    def do_transfer(zone, server) #:nodoc: all
      @transfer_type = Types.new(@transfer_type)
      @state = :InitialSoa
      socket = Socket.tcp(server, @port, @src_address, connect_timeout: @connect_timeout)
      # socket = TCPSocket.new(server, @port, @src_address)
      begin
        #  Send an initial query
        msg = Message.new(zone, @transfer_type, @klass)
        if @transfer_type == Types.IXFR
          rr = RR.create("#{zone} 0 IN SOA" + '0 0 %u 0 0 0 0' % @serial)
          msg.add_authority(rr)
        end
        send_message(socket, msg)

        while (@state != :End)
          response = receive_message(socket)

          if (@state == :InitialSoa)
            rcode = response.rcode
            if (rcode != RCode.NOERROR)
              if (@transfer_type == Types.IXFR &&
                    rcode == RCode.NOTIMP)
                #  IXFR didn't work - let's try AXFR
                Dnsruby.log.debug("IXFR DID NOT WORK (rcode = NOTIMP) - TRYING AXFR!!")
                @state = :InitialSoa
                @transfer_type=Types.AXFR
                #  Send an initial AXFR query
                msg = Message.new(zone, @transfer_type, @klass)
                send_message(socket, msg)
                next
              end
              raise ResolvError.new(rcode.string);
            end

            if (response.question[0].qtype != @transfer_type)
              raise ResolvError.new("invalid question section")
            end

            if (response.header.ancount == 0 && @transfer_type == Types.IXFR)
              Dnsruby.log.debug("IXFR DID NOT WORK (ancount = 0) - TRYING AXFR!!")
              #  IXFR didn't work - let's try AXFR
              @transfer_type=Types.AXFR
              #  Send an initial AXFR query
              @state = :InitialSoa
              msg = Message.new(zone, @transfer_type, @klass)
              send_message(socket, msg)
              next
            end
          end

          response.each_answer { |rr|
            parseRR(rr)
          }
          if (@state == :End &&
                response.tsigstate == :Intermediate)
            raise ResolvError.new("last message must be signed")
          end
          if (@state == :End && @tsig)
            if (response.tsigstate != :Verified)
              @last_tsigstate = :Failed
              raise ResolvError.new("Zone transfer not correctly signed")
            end
            @last_tsigstate = :Verified
          end
        end
        #  This could return with an IXFR response, or an AXFR response.
        #  If it fails completely, then try to send an AXFR query.
        #  Once the query has been sent, then enter the main response loop.
        #  Unless we know we're definitely AXFR, we should be prepared for either IXFR or AXFR
        #  AXFR response : The first and the last RR of the response is the SOA record of the zone.
        #                  The whole zone is returned inbetween.
        #  IXFR response : one or more difference sequences is returned.  The list of difference
        #                  sequences is preceded and followed by a copy of the server's current
        #                  version of the SOA.
        #                  Each difference sequence represents one update to the zone (one SOA
        #                  serial change) consisting of deleted RRs and added RRs.  The first RR
        #                  of the deleted RRs is the older SOA RR and the first RR of the added
        #                  RRs is the newer SOA RR.
        socket.close
        if (@axfr!=nil)
          return @axfr
        end
        return @ixfr
      rescue Exception => e
        socket.close
        raise e
      end
    end

    #  All changes between two versions of a zone in an IXFR response.
    class Delta

      #  The starting serial number of this delta.
      attr_accessor :start

      #  The ending serial number of this delta.
      attr_accessor :end

      #  A list of records added between the start and end versions
      attr_accessor :adds

      #  A list of records deleted between the start and end versions
      attr_accessor :deletes

      def initialize()
        @adds = []
        @deletes = []
      end

      def to_s
        ret = "Adds : " + @adds.join(",")
        ret +=", Deletes : " + @deletes.join(",")
      end
    end

    # Compare two serials according to RFC 1982. Return 0 if equal,
    # -1 if s1 is bigger, 1 if s1 is smaller.
    def compare_serial(s1, s2)
      if s1 == s2
        return 0
      end
      if s1 < s2 and (s2 - s1) < (2**31)
        return 1
      end
      if s1 > s2 and (s1 - s2) > (2**31)
        return 1
      end
      if s1 < s2 and (s2 - s1) > (2**31)
        return -1
      end
      if s1 > s2 and (s1 - s2) < (2**31)
        return -1
      end
      return 0
    end

    def parseRR(rec) #:nodoc: all
      name = rec.name
      type = rec.type
      delta = Delta.new

      case @state
      when :InitialSoa
        if (type != Types.SOA)
          raise ResolvError.new("missing initial SOA")
        end
        @initialsoa = rec
        #  Remember the serial number in the initial SOA; we need it
        #  to recognize the end of an IXFR.
        @end_serial = rec.serial
        #         if ((@transfer_type == Types.IXFR) && (@end_serial <= @serial))
        if ((@transfer_type == Types.IXFR) && (compare_serial(@end_serial, @serial) >= 0))
          Dnsruby.log.debug("zone up to date")
          raise ZoneSerialError.new("IXFR up to date: expected serial " +
              @serial.to_s + " , got " + rec.serial.to_s);
          @state = :End
        else
          @state = :FirstData
        end
      when :FirstData
        #  If the transfer begins with 1 SOA, it's an AXFR.
        #  If it begins with 2 SOAs, it's an IXFR.
        if (@transfer_type == Types.IXFR && type == Types.SOA &&
              rec.serial == @serial)
          Dnsruby.log.debug("IXFR response - using IXFR")
          @rtype = Types.IXFR
          @ixfr = []
          @state = :Ixfr_DelSoa
        else
          Dnsruby.log.debug("AXFR response - using AXFR")
          @rtype = Types.AXFR
          @transfer_type = Types.AXFR
          @axfr = []
          @axfr << @initialsoa
          @state = :Axfr
        end
        parseRR(rec) # Restart...
        return

      when :Ixfr_DelSoa
        delta = Delta.new
        @ixfr.push(delta)
        delta.start = rec.serial
        delta.deletes << rec
        @state = :Ixfr_Del

      when :Ixfr_Del
        if (type == Types.SOA)
          @current_serial = rec.serial
          @state = :Ixfr_AddSoa
          parseRR(rec); # Restart...
          return;
        end
        delta = @ixfr[@ixfr.length - 1]
        delta.deletes << rec

      when :Ixfr_AddSoa
        delta = @ixfr[@ixfr.length - 1]
        delta.end = rec.serial
        delta.adds << rec
        @state = :Ixfr_Add

      when :Ixfr_Add
        if (type == Types.SOA)
          soa_serial = rec.serial
          if (soa_serial == @end_serial)
            @state = :End
            return
          elsif (soa_serial != @current_serial)
            raise ZoneSerialError.new("IXFR out of sync: expected serial " +
                @current_serial.to_s + " , got " + soa_serial.to_s);
          else
            @state = :Ixfr_DelSoa
            parseRR(rec); # Restart...
            return;
          end
        end
        delta = @ixfr[@ixfr.length - 1]
        delta.adds << rec

      when :Axfr
        #  Old BINDs sent cross class A records for non IN classes.
        if (type == Types.A && rec.klass() != @klass)
        else
          if (type == Types.SOA)
            @state = :End
          else
            @axfr << rec
          end
        end
      when :End
        raise ResolvError.new("extra data in zone transfer")

      else
        raise ResolvError.new("invalid state for zone transfer")
      end
    end


    def send_message(socket, msg) #:nodoc: all
      if (@tsig)
        @tsig.apply(msg)
        @tsig = msg.tsig
      end
      query_packet = msg.encode
      lenmsg = [query_packet.length].pack('n')
      socket.send(lenmsg, 0)
      socket.send(query_packet, 0)
    end

    def tcp_read(socket, len) #:nodoc: all
      buf=""
      while (buf.length < len) and not socket.eof? do
        buf += socket.read(len-buf.length)
      end
      return buf
    end

    def receive_message(socket) #:nodoc: all
      buf = tcp_read(socket, 2)
      answersize = buf.unpack('n')[0]
      #  Some servers (e.g. dnscache) apparently hang up on some connections.
      #  Thanks to Matt Palmer for the fix.
      raise ResolvError.new("Server did not send a valid answer") if answersize.nil?
      buf = tcp_read(socket, answersize)
      msg = Message.decode(buf)
      if (@tsig)
        if !@tsig.verify_envelope(msg, buf)
          Dnsruby.log.error("Bad signature on zone transfer - closing connection")
          raise ResolvError.new("Bad signature on zone transfer")
        end
      end
      return msg
    end
  end
end
