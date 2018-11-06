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
require 'dnsruby/select_thread'
require 'ipaddr'
# require 'dnsruby/iana_ports'
module Dnsruby

  class PacketSender # :nodoc: all

    include Socket::Constants

    @@authoritative_cache = Cache.new
    @@recursive_cache = Cache.new


    def PacketSender.cache(query, response)
      return if response.cached
      #  ONLY cache the response if it is not an update response
      question = query.question()[0]
      if (query.do_caching && (query.class != Update) &&
          (question.qtype != Types::AXFR) && (question.qtype != Types::IXFR) &&
          (response.rcode == RCode::NOERROR) &&(!response.tsig) &&
          (query.class != Update) &&
          (response.header.ancount > 0))
        # # @TODO@ What about TSIG-signed responses?
        #  Don't cache any packets with "*" in the query name! (RFC1034 sec 4.3.3)
        if (!question.qname.to_s.include? "*")
          #  Now cache response RRSets
          if (query.header.rd)
            PacketSender.cache_recursive(response);
          else
            PacketSender.cache_authoritative(response);
          end
        end
      end
    end

    def PacketSender.cache_authoritative(answer)
      return if !answer.header.aa
      @@authoritative_cache.add(answer)
    end

    def PacketSender.cache_recursive(answer)
      @@recursive_cache.add(answer)
    end

    def PacketSender.clear_caches
      @@recursive_cache.clear
      @@authoritative_cache.clear
    end

    def PacketSender.recursive_cache_length
      @@recursive_cache.length
    end

    attr_accessor :packet_timeout

    #  The port on the resolver to send queries to.
    # 
    #  Defaults to 53
    attr_accessor :port

    #  Use TCP rather than UDP as the transport.
    # 
    #  Defaults to false
    attr_accessor :use_tcp

    # Reuse tcp connection
    #
    # Defaults to false
    attr_accessor :tcp_pipelining

    # Limit the number of queries per pipeline
    attr_accessor :tcp_pipelining_max_queries

    #  Use UDP only - don't use TCP
    #  For test/debug purposes only
    #  Defaults to false
    attr_accessor :no_tcp

    #  The TSIG record to sign/verify messages with
    attr_reader :tsig

    #  Don't worry if the response is truncated - return it anyway.
    # 
    #  Defaults to false
    attr_accessor :ignore_truncation

    #  The source address to send queries from
    # 
    #  Defaults to localhost
    attr_reader :src_address

    #  should the Recursion Desired bit be set on queries?
    # 
    #  Defaults to true
    attr_accessor :recurse

    #  The max UDP packet size
    # 
    #  Defaults to 512
    attr_reader :udp_size

    #  The address of the resolver to send queries to
    attr_reader :server

    #  Use DNSSEC for this PacketSender
    #  dnssec defaults to ON
    attr_reader :dnssec

    #  Set the source address. If the arg is nil, do nothing
    def src_address6=(arg)
      if (not arg.nil?)
        @src_address6 = arg
      end
    end

    #  Set the source address. If the arg is nil, do nothing
    def src_address=(arg)
      if (not arg.nil?)
        @src_address = arg
      end
    end

    # Sets the TSIG to sign outgoing messages with.
    # Pass in either a Dnsruby::RR::TSIG, or a key_name and key (or just a key)
    # Pass in nil to stop tsig signing.
    # It is possible for client code to sign packets prior to sending - see
    # Dnsruby::RR::TSIG#apply and Dnsruby::Message#sign
    # Note that pre-signed packets will not be signed by PacketSender.
    # * res.tsig=(tsig_rr)
    # * res.tsig=(key_name, key)
    # * res.tsig=nil # Stop the resolver from signing
    def tsig=(*args)
      @tsig = Resolver.get_tsig(args)
    end

    def dnssec=(on)
      @dnssec=on
      if (on)
        #  Set the UDP size (RFC 4035 section 4.1)
        if (udp_packet_size < Resolver::MinDnssecUdpSize)
          self.udp_size = Resolver::MinDnssecUdpSize
        end
      end
    end


    def udp_size=(size)
      @udp_size = size
    end

    def server=(server)
      Dnsruby.log.debug { "InternalResolver setting server to #{server}" }
      @server=Config.resolve_server(server)
      check_ipv6
    end

    #  Can take a hash with the following optional keys :
    # 
    #  * :server
    #  * :port
    #  * :use_tcp
    #  * :tcp_pipelining
    #  * :tcp_pipelining_max_queries
    #  * :no_tcp
    #  * :ignore_truncation
    #  * :src_address
    #  * :src_address6
    #  * :src_port
    #  * :udp_size
    #  * :tsig
    #  * :packet_timeout
    #  * :recurse
    def initialize(*args)
      arg=args[0]
      @ipv6 = false
      @packet_timeout = Resolver::DefaultPacketTimeout
      @port = Resolver::DefaultPort
      @udp_size = Resolver::DefaultUDPSize
      @dnssec = Resolver::DefaultDnssec
      @use_tcp = false
      @no_tcp = false
      @tsig = nil
      @ignore_truncation = false
      @src_address = '0.0.0.0'
      @src_address6 = '::'
      @src_port = [0]
      @recurse = true
      @tcp_pipelining = false
      @tcp_pipelining_max_queries = :infinite
      @use_counts = {}

      if (arg==nil)
        #  Get default config
        config = Config.new
        #         @server = config.nameserver[0]
      elsif (arg.kind_of? String)
        @server=arg
      elsif (arg.kind_of? Name)
        @server=arg
      elsif (arg.kind_of? Hash)
        arg.keys.each do |attr|
          begin
            if (((attr.to_s == "src_address")||(attr.to_s == "src_address6")) &&
                ((arg[attr] == nil) || (arg[attr] == "")))
            else
              send(attr.to_s+"=", arg[attr])
            end
          rescue Exception => e
            Dnsruby.log.error { "PacketSender : Argument #{attr}, #{arg[attr]} not valid : #{e}\n" }
          end
          #         end
        end
      end
      # Check server is IP
      @server=Config.resolve_server(@server)

      check_ipv6
      #       ResolverRegister::register_single_resolver(self)
    end

    def check_ipv6
      begin
        i = IPv4.create(@server)
        #         @src_address = '0.0.0.0'
        @ipv6=false
      rescue Exception
        begin
          i = IPv6.create(@server)
          #           @src_address6 = '::'
          @ipv6=true
        rescue Exception
          Dnsruby.log.error { "Server is neither IPv4 or IPv6!\n" }
        end
      end
    end

    def close
      #  @TODO@ What about closing?
      #  Any queries to complete? Sockets to close?
    end

    # Asynchronously send a Message to the server. The send can be done using just
    # Dnsruby. Support for EventMachine has been deprecated.
    # 
    # == Dnsruby pure Ruby event loop :
    # 
    # A client_queue is supplied by the client,
    # along with an optional client_query_id to identify the response. The client_query_id
    # is generated, if not supplied, and returned to the client.
    # When the response is known, the tuple
    # (query_id, response_message, response_exception) is put in the queue for the client to process.
    # 
    # The query is sent synchronously in the caller's thread. The select thread is then used to
    # listen for and process the response (up to pushing it to the client_queue). The client thread
    # is then used to retrieve the response and deal with it.
    # 
    # Takes :
    # 
    # * msg - the message to send
    # * client_queue - a Queue to push the response to, when it arrives
    # * client_query_id - an optional ID to identify the query to the client
    # * use_tcp - whether to use TCP (defaults to PacketSender.use_tcp)
    # 
    # Returns :
    # 
    # * client_query_id - to identify the query response to the client. This ID is
    # generated if it is not passed in by the client
    # 
    # If the native Dsnruby networking layer is being used, then this method returns the client_query_id
    # 
    #     id = res.send_async(msg, queue)
    #     NOT SUPPORTED : id = res.send_async(msg, queue, use_tcp)
    #     id = res.send_async(msg, queue, id)
    #     id = res.send_async(msg, queue, id, use_tcp)
    # 
    # Use Message#send_raw to send the packet with an untouched header.
    # Use Message#do_caching to tell dnsruby whether to check the cache before
    # sending, and update the cache upon receiving a response.
    # Use Message#do_validation to tell dnsruby whether or not to do DNSSEC
    # validation for this particular packet (assuming SingleResolver#dnssec == true)
    # Note that these options should not normally be used!
    def send_async(*args) # msg, client_queue, client_query_id, use_tcp=@use_tcp)
      #  @TODO@ Need to select a good Header ID here - see forgery-resilience RFC draft for details
      msg = args[0]
      client_query_id = nil
      client_queue = nil
      use_tcp = @use_tcp
      if (msg.kind_of? String)
        msg = Message.new(msg)
        if (@dnssec)
          msg.header.cd = @dnssec # we'll do our own validation by default
          if (Dnssec.no_keys?)
            msg.header.cd = false
          end
        end
      end
      if (args.length > 1)
        if (args[1].class==Queue)
          client_queue = args[1]
        elsif (args.length == 2)
          use_tcp = args[1]
        end
        if (args.length > 2)
          client_query_id = args[2]
          if (args.length > 3)
            use_tcp = args[3]
          end
        end
      end
      #  Need to keep track of the request mac (if using tsig) so we can validate the response (RFC2845 4.1)
      #       #Are we using EventMachine or native Dnsruby?
      #       if (Resolver.eventmachine?)
      #         return send_eventmachine(query_packet, msg, client_query_id, client_queue, use_tcp)
      #       else
      if (!client_query_id)
        client_query_id = Time.now + rand(10000) # is this safe?!
      end

      begin
        query_packet = make_query_packet(msg, use_tcp)
      rescue EncodeError => err
        Dnsruby.log.error { "#{err}" }
        st = SelectThread.instance
        st.push_exception_to_select(client_query_id, client_queue, err, nil)
        return
      end

      if (msg.do_caching && (msg.class != Update))
        #  Check the cache!!
        cachedanswer = nil
        if (msg.header.rd)
          cachedanswer = @@recursive_cache.find(msg.question()[0].qname, msg.question()[0].type)
        else
          cachedanswer = @@authoritative_cache.find(msg.question()[0].qname, msg.question()[0].type)
        end
        if (cachedanswer)
          TheLog.debug("Sending cached answer to client\n")
          #  @TODO@ Fix up the header - ID and flags
          cachedanswer.header.id = msg.header.id
          #  If we can find the answer, send it to the client straight away
          #  Post the result to the client using SelectThread
          st = SelectThread.instance
          st.push_response_to_select(client_query_id, client_queue, cachedanswer, msg, self)
          return client_query_id
        end
      end
      #  Otherwise, run the query
      if (udp_packet_size < query_packet.length)
        if (@no_tcp)
          #  Can't send the message - abort!
          err=IOError.new("Can't send message - too big for UDP and no_tcp=true")
          Dnsruby.log.error { "#{err}" }
          st.push_exception_to_select(client_query_id, client_queue, err, nil)
          return
        end
        Dnsruby.log.debug { "Query packet length exceeds max UDP packet size - using TCP" }
        use_tcp = true
      end
      send_dnsruby(query_packet, msg, client_query_id, client_queue, use_tcp)
      return client_query_id
      #       end
    end

    #  This method returns the current tcp socket for pipelining
    #  If this is the first time the method is called then the socket is bound to
    #  @src_address:@src_port and connected to the remote dns server @server:@port.
    #  If the connection has been closed because of an EOF on recv_nonblock (closed by server)
    #  the function will recreate of the socket (since @pipeline_socket.connect will result in a IOError
    #  exception)
    #  In general, every subsequent call the function will either return the current tcp
    #  pipeline socket or a new connected socket if the current one was closed by the server
    def tcp_pipeline_socket(src_port)
      Dnsruby.log.debug("Using tcp_pipeline_socket")
      sockaddr = Socket.sockaddr_in(@port, @server)

      reuse_pipeline_socket = -> do
        begin
          max = @tcp_pipelining_max_queries
          use_count = @use_counts[@pipeline_socket]
          if use_count && max != :infinite && use_count >= max
             #we can't reuse the socket since max is reached
            @use_counts.delete(@pipeline_socket)
            @pipeline_socket = nil
            Dnsruby.log.debug("Max queries per connection attained - creating new socket")
          else
            @pipeline_socket.connect(sockaddr)
          end
        rescue Errno::EISCONN
          #already connected, do nothing and reuse!
        rescue IOError, Errno::ECONNRESET #close by remote host, reconnect
          @pipeline_socket = nil
          Dnsruby.log.debug("Connection closed - recreating socket")
        end
      end

      create_pipeline_socket = -> do
        @tcp_pipeline_local_port = src_port
        src_address = @ipv6 ? @src_address6 : @src_address
        begin
          @pipeline_socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          @pipeline_socket.bind(Addrinfo.tcp(src_address, src_port))
          @pipeline_socket.connect(sockaddr)
          Dnsruby.log.debug("Creating socket #{src_address}:#{src_port}")
          @use_counts[@pipeline_socket] = 0
        rescue Exception => e
          @pipeline_socket = nil
          raise e
        end
      end

      # Don't combine the following 2 statements; the reuse lambda can set the
      # socket to nil and if so we'd want to call the create lambda to recreate it.
      reuse_pipeline_socket.() if @pipeline_socket
      new_socket = @pipeline_socket.nil?
      create_pipeline_socket.() unless @pipeline_socket

      @use_counts[@pipeline_socket] += 1

      [@pipeline_socket, new_socket]
    end

    #  This method sends the packet using the built-in pure Ruby event loop, with no dependencies.
    def send_dnsruby(query_bytes, query, client_query_id, client_queue, use_tcp) #:nodoc: all
      endtime = Time.now + @packet_timeout
      #  First send the query (synchronously)
      st = SelectThread.instance
      socket = nil
      runnextportloop = true
      numtries = 0
      src_address = @src_address
      if (@ipv6)
        src_address = @src_address6
      end
      while (runnextportloop) do
        begin
          numtries += 1
          src_port = get_next_src_port
          if (use_tcp)
            begin
              if (@tcp_pipelining)
                socket, new_socket = tcp_pipeline_socket(src_port)
                src_port = @tcp_pipeline_local_port
              else
                socket = TCPSocket.new(@server, @port, src_address, src_port)
                new_socket = true
              end
            rescue Errno::EBADF, Errno::ENETUNREACH => e
              #  Can't create a connection
              err=IOError.new("TCP connection error to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}, exception = #{e.class}, #{e}")
              Dnsruby.log.error { "#{err}" }
              st.push_exception_to_select(client_query_id, client_queue, err, nil)
              return
            end
          else
            socket = nil
            #  JRuby UDPSocket only takes 0 parameters - no IPv6 support in JRuby...
            if (/java/ =~ RUBY_PLATFORM)
              socket = UDPSocket.new()
            else
              #               ipv6 = @src_address =~ /:/
              socket = UDPSocket.new(@ipv6 ? Socket::AF_INET6 : Socket::AF_INET)
            end
            new_socket = true
            socket.bind(src_address, src_port)
            socket.connect(@server, @port)
          end
          runnextportloop = false
        rescue Exception => e
          if (socket!=nil)
            begin
              #let the select thread close the socket if tcp_pipeli
              socket.close unless @tcp_pipelining && !new_socket
            rescue Exception
            end
          end
          #  Try again if the error was EADDRINUSE and a random source port is used
          #  Maybe try a max number of times?
          if ((e.class != Errno::EADDRINUSE) || (numtries > 50) ||
              ((e.class == Errno::EADDRINUSE) && (src_port == @src_port[0])))
            err_msg = "dnsruby can't connect to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}, exception = #{e.class}, #{e} #{e.backtrace}"
            err=IOError.new(err_msg)
            Dnsruby.log.error( "#{err}")
            Dnsruby.log.error(e.backtrace)
            if @tcp_pipelining
              st.push_exception_to_select(client_query_id, client_queue, SocketEofResolvError.new(err_msg), nil)
            else
              st.push_exception_to_select(client_query_id, client_queue, err, nil)
            end
            return
          end
        end
      end
      if (socket==nil)
        err=IOError.new("dnsruby can't connect to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}")
        Dnsruby.log.error { "#{err}" }
        st.push_exception_to_select(client_query_id, client_queue, err, nil)
        return
      end
      Dnsruby.log.debug { "Sending packet to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp} : #{query.question()[0].qname}, #{query.question()[0].qtype}" }
      #             print "#{Time.now} : Sending packet to #{@server} : #{query.question()[0].qname}, #{query.question()[0].qtype}\n"
      #  Listen for the response before we send the packet (to avoid any race conditions)
      query_settings = SelectThread::QuerySettings.new(query_bytes, query, @ignore_truncation, client_queue, client_query_id, socket, @server, @port, endtime, udp_packet_size, self)
      query_settings.is_persistent_socket = @tcp_pipelining if use_tcp
      query_settings.tcp_pipelining_max_queries = @tcp_pipelining_max_queries if @tcp_pipelining
      begin
        if (use_tcp)
          lenmsg = [query_bytes.length].pack('n')
          socket.send(lenmsg, 0)
        end
        socket.send(query_bytes, 0)

        #  The select thread will now wait for the response and send that or a
        #  timeout back to the client_queue.
        st.add_to_select(query_settings)
      rescue Exception => e
        err_msg = "Send failed to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}, exception : #{e}"
        err=IOError.new(err_msg)
        Dnsruby.log.error { "#{err}" }
        Dnsruby.log.error(e.backtrace)
        if @tcp_pipelining
          st.push_exception_to_select(client_query_id, client_queue, SocketEofResolvError.new(err_msg), nil) if new_socket
        else
          st.push_exception_to_select(client_query_id, client_queue, err, nil)
        end
        begin
          #we let the select_thread close the socket when doing tcp
          #pipelining
          socket.close unless @tcp_pipelining && !new_socket
        rescue Exception
        end
        return
      end

      Dnsruby.log.debug { "Packet sent to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp} : #{query.question()[0].qname}, #{query.question()[0].qtype}" }
      #       print "Packet sent to #{@server}:#{@port} from #{@src_address}:#{src_port}, use_tcp=#{use_tcp} : #{query.question()[0].qname}, #{query.question()[0].qtype}\n"
    end

    #  The source port to send queries from
    #  Returns either a single Integer or an Array
    #  e.g. "0", or "[60001, 60002, 60007]"
    # 
    #  Defaults to 0 - random port
    def src_port
      if (@src_port.length == 1)
        return @src_port[0]
      end
      return @src_port
    end

    #  Can be a single Integer or a Range or an Array
    #  If an invalid port is selected (one reserved by
    #  IANA), then an ArgumentError will be raised.
    # 
    #         res.src_port=0
    #         res.src_port=[60001,60005,60010]
    #         res.src_port=60015..60115
    # 
    def src_port=(p)
      @src_port=[]
      add_src_port(p)
    end

    #  Can be a single Integer or a Range or an Array
    #  If an invalid port is selected (one reserved by
    #  IANA), then an ArgumentError will be raised.
    #  "0" means "any valid port" - this is only a viable
    #  option if it is the only port in the list.
    #  An ArgumentError will be raised if "0" is added to
    #  an existing set of source ports.
    # 
    #         res.add_src_port(60000)
    #         res.add_src_port([60001,60005,60010])
    #         res.add_src_port(60015..60115)
    # 
    def add_src_port(p)
      if (Resolver.check_port(p, @src_port))
        a = Resolver.get_ports_from(p)
        a.each do |x|
          if ((@src_port.length > 0) && (x == 0))
            raise ArgumentError.new("src_port of 0 only allowed as only src_port value (currently #{@src_port.length} values")
          end
          @src_port.push(x)
        end
      end
    end


    def get_next_src_port
      # Different OSes have different interpretations of "random port" here.
      # Apparently, Linux will just give you the same port as last time, unless it is still
      # open, in which case you get n+1.
      # We need to determine an actual (random) number here, then ask the OS for it, and
      # continue until we get one.
      if (@src_port[0] == 0)
        candidate = -1
        #         # better to construct an array of all the ports we *can* use, and then just pick one at random!
        #         candidate = Iana::UNRESERVED_PORTS[rand(Iana::UNRESERVED_PORTS.length())]
        #         #        while (!(Resolver.port_in_range(candidate)))
        #         #          candidate = (rand(65535-1024) + 1024)
        #         #        end
        #  @TODO@ Should probably construct a bitmap of the IANA ports...
        candidate = 50000 + (rand(15535)) # pick one over 50000
        return candidate
      end
      pos = rand(@src_port.length)
      return @src_port[pos]
    end

    def check_response(response, response_bytes, query, client_queue, client_query_id, tcp)
      #  @TODO@ Should send_raw avoid this?
      if (!query.send_raw)
        sig_value = check_tsig(query, response, response_bytes)
        if (sig_value != :okay)
          #  Should send error back up to Resolver here, and then NOT QUERY AGAIN!!!
          return sig_value
        end
        if ((response.header.get_header_rcode == RCode.FORMERR) &&
            (query.header.arcount == 0))
          # Raise an error
          return true
        end
        #  Should check that question section is same as question that was sent! RFC 5452
        #  If it's not an update...
        if (query.class == Update)
          #  @TODO@!!
        else
          if ((response.question.size == 0) ||
              (response.question[0].qname.labels != query.question[0].qname.labels) ||
              (response.question[0].qtype != query.question[0].qtype) ||
              (response.question[0].qclass != query.question[0].qclass) ||
              (response.question.length != query.question.length) ||
              (response.header.id != query.header.id))
            TheLog.info("Incorrect packet returned : #{response.to_s}")
            return false
          end
        end
        # end
        #  IF WE GET FORMERR BACK HERE (and we have EDNS0 on) THEN
        #  TRY AGAIN WITH NO OPT RECORDS! (rfc2671 section 5.3)
        if ((response.header.get_header_rcode == RCode.FORMERR) &&
            (query.header.arcount > 0))
          #  try resending the message with no OPT record
          query.remove_additional
          query.send_raw = true
          send_async(query, client_queue, client_query_id, false)
          return false
        end
        if (response.header.tc && !tcp && !@ignore_truncation)
          if (@no_tcp)
            Dnsruby.log.debug { "Truncated response - not resending over TCP as no_tcp==true" }
          else
            #  Try to resend over tcp
            Dnsruby.log.debug { "Truncated - resending over TCP" }
            #  @TODO@ Are the query options used correctly here? DNSSEC in particular...
            #         query.send_raw = true # Make sure that the packet is not messed with.
            send_async(query, client_queue, client_query_id, true)
            return false
          end
        end
      end
      return true
    end

    def check_tsig(query, response, response_bytes)
      if (query.tsig)
        if (response.tsig)
          if !query.tsig.verify(query, response, response_bytes)
            #  Discard packet and wait for correctly signed response
            Dnsruby.log.error { "TSIG authentication failed!" }
            return TsigError.new
          end
        else
          #  Treated as having format error and discarded (RFC2845, 4.6)
          #  but return a different error code, because some servers fail at
          #  this
          Dnsruby.log.error { "Expecting TSIG signed response, but got unsigned response - discarding" }
          return TsigNotSignedResponseError.new
        end
      elsif (response.tsig)
        #  Error - signed response to unsigned query
        Dnsruby.log.error { "Signed response to unsigned query" }
        return TsigError.new
      end
      return :okay
    end

    def make_query(name, type = Types::A, klass = Classes::IN, set_cd=@dnssec)
      msg = Message.new
      msg.header.rd = 1
      msg.add_question(name, type, klass)
      if (@dnssec)
        msg.header.cd = set_cd # We do our own validation by default
      end
      return msg
    end

    #  Prepare the packet for sending
    def make_query_packet(packet, use_tcp = @use_tcp) #:nodoc: all
      if (!packet.send_raw) # Don't mess with this packet!
        if (packet.header.opcode == OpCode.QUERY || @recurse)
          packet.header.rd=@recurse
        end

        #  Only do this if the packet has not been prepared already!
        if (@dnssec)
          prepare_for_dnssec(packet)
        elsif ((udp_packet_size > Resolver::DefaultUDPSize) && !use_tcp)
          #       if ((udp_packet_size > Resolver::DefaultUDPSize) && !use_tcp)
          #  @TODO@ What if an existing OPT RR is not big enough? Should we replace it?
          add_opt_rr(packet)
        end
      end

      if (@tsig && !packet.signed?)
        @tsig.apply(packet)
      end
      return packet.encode
    end

    def add_opt_rr(packet)
      Dnsruby.log.debug { ";; Adding EDNS extension with UDP packetsize  #{udp_packet_size}.\n" }
      #  RFC 3225
      optrr = RR::OPT.new(udp_packet_size)

      #  Only one OPT RR allowed per packet - do we already have one?
      if (packet.additional.rrset(packet.question()[0].qname, Types::OPT).rrs.length == 0)
        packet.add_additional(optrr)
      end
    end

    def prepare_for_dnssec(packet)
      #  RFC 4035
      Dnsruby.log.debug { ";; Adding EDNS extension with UDP packetsize #{udp_packet_size} and DNS OK bit set\n" }
      optrr = RR::OPT.new(udp_packet_size) # Decimal UDPpayload
      optrr.dnssec_ok=true

      if (packet.additional.rrset(packet.question()[0].qname, Types::OPT).rrs.length == 0)
        packet.add_additional(optrr)
      end

      packet.header.ad = false # RFC 4035 section 4.6

      #  SHOULD SET CD HERE!!!
      if (packet.do_validation)
        packet.header.cd = true
      end
      if (Dnssec.no_keys?)
        packet.header.cd = false
      end

    end

    #  Return the packet size to use for UDP
    def udp_packet_size
      #  if @udp_size > DefaultUDPSize then we use EDNS and
      #  @udp_size should be taken as the maximum packet_data length
      ret = (@udp_size > Resolver::DefaultUDPSize ? @udp_size : Resolver::DefaultUDPSize)
      return ret
    end
  end
end
