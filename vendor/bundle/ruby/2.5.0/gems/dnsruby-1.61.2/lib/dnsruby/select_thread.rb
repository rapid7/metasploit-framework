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
require 'socket'
# require 'thread'
begin
  require 'fastthread'
rescue LoadError
  require 'thread'
end
require 'set'
require 'singleton'
require 'dnsruby/validator_thread.rb'
module Dnsruby
  class SelectThread #:nodoc: all
    class SelectWakeup < RuntimeError; end
    include Singleton
    #  This singleton class runs a continuous select loop which
    #  listens for responses on all of the in-use sockets.
    #  When a new query is sent, the thread is woken up, and
    #  the socket is added to the select loop (and the new timeout
    #  calculated).
    #  Note that a combination of the socket and the packet ID is
    #  sufficient to uniquely identify the query to the select thread.
    # 
    #  But how do we find the response queue for a particular query?
    #  Hash of client_id->[query, client_queue, socket]
    #  and socket->[client_id]
    # 
    #  @todo@ should we implement some of cancel function?

    def initialize
      @@mutex = Mutex.new
      @@mutex.synchronize {
        @@in_select=false
        #         @@notifier,@@notified=IO.pipe
        @@sockets = Set.new
        @@timeouts = Hash.new
        #     @@mutex.synchronize do
        @@query_hash = Hash.new
        @@socket_hash = Hash.new
        @@socket_is_persistent = Hash.new
        @@observers = Hash.new
        @@tcp_buffers=Hash.new
        @@socket_remaining_queries = Hash.new
        @@tick_observers = []
        @@queued_exceptions=[]
        @@queued_responses=[]
        @@queued_validation_responses=[]
        @@wakeup_sockets = get_socket_pair
        @@sockets << @@wakeup_sockets[1]

        #  Suppress reverse lookups
        BasicSocket.do_not_reverse_lookup = true
        #     end
        #  Now start the select thread
        @@select_thread = Thread.new { do_select }

        #         # Start the validator thread
        #         @@validator = ValidatorThread.instance
      }
    end

    def get_socket_pair
      #  Emulate socketpair on platforms which don't support it
      srv = nil
      begin
        srv = TCPServer.new('localhost', 0)
      rescue Errno::EADDRNOTAVAIL, SocketError # OSX Snow Leopard issue - need to use explicit IP
        begin
          srv = TCPServer.new('127.0.0.1', 0)
        rescue Error # Try IPv6
          srv = TCPServer.new('::1', 0)
        end
      end
      rsock = TCPSocket.new(srv.addr[3], srv.addr[1])
      lsock = srv.accept
      srv.close
      return [lsock, rsock]
    end

    class QuerySettings
      attr_accessor :query_bytes, :query, :ignore_truncation, :client_queue,
        :client_query_id, :socket, :dest_server, :dest_port, :endtime, :udp_packet_size,
        :single_resolver, :is_persistent_socket, :tcp_pipelining_max_queries
      #  new(query_bytes, query, ignore_truncation, client_queue, client_query_id,
      #      socket, dest_server, dest_port, endtime, , udp_packet_size, single_resolver)
      def initialize(*args)
        @query_bytes = args[0]
        @query = args[1]
        @ignore_truncation=args[2]
        @client_queue = args[3]
        @client_query_id = args[4]
        @socket = args[5]
        @dest_server = args[6]
        @dest_port=args[7]
        @endtime = args[8]
        @udp_packet_size = args[9]
        @single_resolver = args[10]
        @is_persistent_socket = false
        @tcp_pipelining_max_queries = nil
      end
    end

    def tcp?(socket)
      type = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE)
      [Socket::SOCK_STREAM].pack("i") == type.data
    end

    def udp?(socket)
      type = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE)
      [Socket::SOCK_DGRAM].pack("i") == type.data
    end

    def add_to_select(query_settings)
      #  Add the query to sockets, and then wake the select thread up
      @@mutex.synchronize {
        check_select_thread_synchronized
        #  @TODO@ This assumes that all client_query_ids are unique!
        #  Would be a good idea at least to check this...
        @@query_hash[query_settings.client_query_id]=query_settings
        @@socket_hash[query_settings.socket] ||= []
        @@socket_hash[query_settings.socket] << query_settings.client_query_id
        @@socket_remaining_queries[query_settings.socket] ||= query_settings.tcp_pipelining_max_queries if query_settings.tcp_pipelining_max_queries != :infinite
        @@timeouts[query_settings.client_query_id]=query_settings.endtime
        @@sockets << query_settings.socket
        @@socket_is_persistent[query_settings.socket] = query_settings.is_persistent_socket
      }
      begin
        @@wakeup_sockets[0].send("wakeup!", 0)
      rescue Exception => e
        #          do nothing
      end
    end

    def check_select_thread_synchronized
      if (!@@select_thread.alive?)
        Dnsruby.log.debug{"Restarting select thread"}
        @@select_thread = Thread.new {
          do_select
        }
      end
    end

    def select_thread_alive?
      ret=true
      @@mutex.synchronize{
        ret = @@select_thread.alive?
      }
      return ret
    end

    def do_select
      unused_loop_count = 0
      last_tick_time = Time.now - 10
      while true do
        if (last_tick_time < (Time.now - 0.5))
          send_tick_to_observers # ONLY NEED TO SEND THIS TWICE A SECOND - NOT EVERY SELECT!!!
          last_tick_time = Time.now
        end
        send_queued_exceptions
        send_queued_responses
        send_queued_validation_responses
        timeout = tick_time = 0.1 # We provide a timer service to various Dnsruby classes
        sockets, timeouts, has_observer = @@mutex.synchronize { [@@sockets.to_a, @@timeouts.values, !@@observers.empty?] }
        if (timeouts.length > 0)
          timeouts.sort!
          timeout = timeouts[0] - Time.now
          if (timeout <= 0)
            process_timeouts
            timeout = 0
            next
          end
        end
        ready=nil
        if (has_observer && (timeout > tick_time))
          timeout = tick_time
        end
        #         next if (timeout < 0)
        begin
          ready, write, errors = IO.select(sockets, nil, nil, timeout)
        rescue SelectWakeup
          #  If SelectWakeup, then just restart this loop - the select call will be made with the new data
          next
        rescue IOError, EncodeError => e
          #           print "IO Error  =: #{e}\n"
          exceptions = clean_up_closed_sockets
          exceptions.each { |exception| send_exception_to_client(*exception) }

          next
        end
        if ready && ready.include?(@@wakeup_sockets[1])
          ready.delete(@@wakeup_sockets[1])
          wakeup_msg = "loop"
          begin
            while wakeup_msg && wakeup_msg.length > 0
              wakeup_msg = @@wakeup_sockets[1].recv_nonblock(20)
            end
          rescue
            #  do nothing
          end
        end
        if (ready == nil)
          #  process the timeouts
          process_timeouts
          unused_loop_count+=1
        else
          process_ready(ready)
          unused_loop_count=0
          # process_error(errors)
        end
        @@mutex.synchronize do
          if (unused_loop_count > 10 && @@query_hash.empty? && @@observers.empty?)
            Dnsruby.log.debug("Try stop select loop")

            non_persistent_sockets = @@sockets.select { |s| ! @@socket_is_persistent[s] }
            non_persistent_sockets.each do |socket|
              socket.close rescue nil
              @@sockets.delete(socket)
            end

            Dnsruby.log.debug("Deleted #{non_persistent_sockets.size} non-persistent sockets," +
                              " #{@@sockets.count} persistent sockets remain.")
            @@socket_hash.clear

            if @@sockets.empty?
              Dnsruby.log.debug("Stopping select loop")
              return
            end
          end
        end
        #               }
      end
    end

    # Removes closed sockets from @@sockets, and returns an array containing 1
    # exception for each closed socket contained in @@socket_hash.
    def clean_up_closed_sockets
      exceptions = @@mutex.synchronize do
        closed_sockets_in_hash = @@sockets.select(&:closed?).select { |s| @@socket_hash[s] }
        @@sockets.delete_if { | socket | socket.closed? }
        closed_sockets_in_hash.each_with_object([]) do |socket, exceptions|
          @@socket_hash[socket].each do | client_id |
            exceptions << [SocketEofResolvError.new("TCP socket closed before all answers received"), socket, client_id]
          end
        end
      end
    end

    def process_error(errors)
      Dnsruby.log.debug{"Error! #{errors.inspect}"}
      #  @todo@ Process errors [can we do this in single socket environment?]
    end

    def get_active_ids(queries, id)
      queries.keys.select { |client_query_id| client_query_id[1].header.id == id }
    end

    #         @@query_hash[query_settings.client_query_id]=query_settings
    def process_ready(ready)
      persistent_sockets, nonpersistent_sockets = @@mutex.synchronize { ready.partition { |socket| persistent?(socket) } }

      nonpersistent_sockets.each do |socket|
        query_settings =  @@mutex.synchronize { @@query_hash[@@socket_hash[socket][0]] }
        next if !query_settings

        udp_packet_size = query_settings.udp_packet_size
        msg, bytes = get_incoming_data(socket, udp_packet_size)

        process_message(msg, bytes, socket) if msg

        ready.delete(socket)
      end

      persistent_sockets.each do |socket|
        msg, bytes = get_incoming_data(socket, 0)
        process_message(msg, bytes, socket) if msg
        ready.delete(socket)
      end
    end

    def process_message(msg, bytes, socket)
      @@mutex.synchronize do
        ids = get_active_ids(@@query_hash, msg.header.id)
        return if ids.empty? # should be only one
        query_settings = @@query_hash[ids[0]].clone
      end

      answerip = msg.answerip.downcase
      answerfrom = msg.answerfrom.downcase
      answeripaddr = IPAddr.new(answerip)
      dest_server = IPAddr.new("0.0.0.0")

      begin
        destserveripaddr = IPAddr.new(dest_server)
      rescue ArgumentError
        #  Host name not IP address
      end

      if (dest_server && (dest_server != '0.0.0.0') &&
          (answeripaddr != destserveripaddr) &&
          (answerfrom != dest_server))
        Dnsruby.log.warn("Unsolicited response received from #{answerip} instead of #{query_settings.dest_server}")
      else
        send_response_to_client(msg, bytes, socket)
      end
    end

    def send_response_to_client(msg, bytes, socket)
      #  Figure out which client_ids we were expecting on this socket, then see if any header ids match up
      #  @TODO@ Can get rid of this, as we only have one query per socket.
      client_ids=[]
      @@mutex.synchronize{
        client_ids = @@socket_hash[socket].clone
      }
      #  get the queries associated with them
      client_ids.each do |id|
        query_header_id=nil
        @@mutex.synchronize{
          query_header_id = @@query_hash[id].query.header.id
        }
        if (query_header_id == msg.header.id)
          #  process the response
          client_queue = nil
          res = nil
          query=nil
          @@mutex.synchronize{
            client_queue = @@query_hash[id].client_queue
            res = @@query_hash[id].single_resolver
            query = @@query_hash[id].query
          }
          tcp = tcp?(socket)
          #  At this point, we should check if the response is OK
          if (ret = res.check_response(msg, bytes, query, client_queue, id, tcp))
            remove_id(id)
            exception = msg.get_exception
            if (ret.kind_of?TsigError)
              exception = ret
            end
            Dnsruby.log.debug{"Pushing response to client queue"}
            push_to_client(id, client_queue, msg, exception, query, res)
            #             client_queue.push([id, msg, exception])
            #             notify_queue_observers(client_queue, id)
          else
            #  Sending query again - don't return response
          end
          return
        end
      end
      #  If not, then we have an error
      Dnsruby.log.error{"Stray packet - " + msg.inspect + "\n from " + socket.inspect}
      print("Stray packet - " + msg.question()[0].qname.to_s + " from " + msg.answerip.to_s + ", #{client_ids.length} client_ids\n")
    end

    def persistent?(socket)
      @@socket_is_persistent[socket]
    end

    def remove_id(id)

      @@mutex.synchronize do
        socket = @@query_hash[id].socket
        @@timeouts.delete(id)
        @@query_hash.delete(id)
        @@socket_hash[socket].delete(id)

        decrement_remaining_queries(socket) if persistent?(socket)

        if !persistent?(socket) || max_attained?(socket)
          @@sockets.delete(socket)
          @@socket_hash.delete(socket)
          Dnsruby.log.debug("Closing socket #{socket}")
          socket.close rescue nil
        end
      end
    end

    def decrement_remaining_queries(socket)
      if @@socket_remaining_queries[socket]
        @@socket_remaining_queries[socket] -= 1
      end
    end

    def max_attained?(socket)
      remaining = @@socket_remaining_queries[socket]
      attained = persistent?(socket) && remaining && remaining <= 0
      Dnsruby.log.debug("Max queries per conn attained") if attained
      attained
    end

    def process_timeouts
      # NOTE: It's @@timeouts we need to protect; after the clone we're ok
      timeouts = @@mutex.synchronize { @@timeouts.clone }
      time_now = Time.now
      timeouts.each do |client_id, timeout|
        if timeout < time_now
          send_exception_to_client(ResolvTimeout.new("Query timed out"), nil, client_id)
        end
      end
    end

    def tcp_read(socket)
      #  Keep buffer for all TCP sockets, and return
      #  to select after reading available data. Once all data has been received,
      #  then process message.
      buf=""
      expected_length = 0
      @@mutex.synchronize {
        buf, expected_length = @@tcp_buffers[socket]
        if (!buf)
          buf = ""
          expected_length = 2
          @@tcp_buffers[socket]=[buf, expected_length]
        end
      }
      if (buf.length() < expected_length)
        begin
          input, = socket.recv_nonblock(expected_length-buf.length)
          if (input=="")
            Dnsruby.log.debug("EOF from server - no bytes read - closing socket")
            socket.close #EOF closed by server, if we were interrupted we need to resend

            exceptions = @@mutex.synchronize do
              @@sockets.delete(socket) #remove ourselves from select, app will have to retry
              #maybe fire an event
              @@socket_hash[socket].map do | client_id |
                [SocketEofResolvError.new("TCP socket closed before all answers received"), socket, client_id]
              end
            end

            exceptions.each { |exception| send_exception_to_client(*exception) }

            return false
          end
          buf << input
        rescue
          #  Oh well - better luck next time!
          return false
        end
      end
      #  If data is complete, then return it.
      if (buf.length == expected_length)
        if (expected_length == 2)
          #  We just read the data_length field. Now we need to start reading that many bytes.
          @@mutex.synchronize {
            answersize = buf.unpack('n')[0]
            @@tcp_buffers[socket] = ["", answersize]
          }
          return tcp_read(socket)
        else
          #  We just read the data - now return it
          @@mutex.synchronize {
            @@tcp_buffers.delete(socket)
          }
          return buf
        end
      else
        @@mutex.synchronize {
          @@tcp_buffers[socket]=[buf, expected_length]
        }
        return false
      end
    end

    def get_incoming_data(socket, packet_size)
      answerfrom,answerip,answerport,answersize=nil
      ans,buf = nil
      is_tcp = tcp?(socket)

      begin
        if is_tcp
          #  Call TCP read here - that will take care of reading the 2 byte length,
          #  and then the full packet - without blocking select.
          buf = tcp_read(socket)
          if (!buf) # Wait for the buffer to comletely fill
            #             handle_recvfrom_failure(socket, "")
            return
          end
        else
          #  @TODO@ Can we get recvfrom to stop issuing PTR queries when we already
          #  know both the FQDN and the IP address?
          if (ret = socket.recvfrom(packet_size))
            buf = ret[0]
            answerport=ret[1][1]
            answerfrom=ret[1][2]
            answerip=ret[1][3]
            answersize=(buf.length)
          else
            #  recvfrom failed - why?
            Dnsruby.log.error{"Error - recvfrom failed from #{socket}"}
            handle_recvfrom_failure(socket, "")
            return
          end
        end
      rescue Exception => e
        Dnsruby.log.error{"Error - recvfrom failed from #{socket}, exception : #{e}"}
        handle_recvfrom_failure(socket, e)
        return
      end
      Dnsruby.log.debug{";; answer from #{answerfrom} : #{answersize} bytes\n"}

      begin
        ans = Message.decode(buf)

        if is_tcp
          @@mutex.synchronize do
            ids = get_active_ids(@@query_hash, ans.header.id)
            if ids.empty?
              Dnsruby.log.error("Decode error from #{answerip} but can't determine packet id")
              #todo add error event? The problem is we don't have a valid id so we don't
              #know which client queue to send the exception to
            end
            answerfrom = @@query_hash[ids[0]].dest_server
            answerip = answerfrom
            answerport = @@query_hash[ids[0]].dest_port
          end
        end

      rescue Exception => e
        Dnsruby.log.error("Decode error! #{e.class}, #{e}\nfor msg (length=#{buf.length}) : #{buf}")
        client_id=get_client_id_from_answerfrom(socket, answerip, answerport)
        if (client_id == nil)
          Dnsruby.log.error{"Decode error from #{answerip} but can't determine packet id"}
        end
        #  We should check if the TC bit is set (if we can get that far)
        if ((DecodeError === e) && (e.partial_message.header.tc))
          Dnsruby.log.error{"Decode error (from {answerip})! Header shows truncation, so trying again over TCP"}
          #  If it is, then we should retry over TCP
          sent = false
          @@mutex.synchronize{
            client_ids = @@socket_hash[socket]
            #  get the queries associated with them
            client_ids.each do |id|
              query_header_id=nil
              query_header_id = @@query_hash[id].query.header.id
              if (query_header_id == e.partial_message.header.id)
                #  process the response
                client_queue = nil
                res = nil
                query=nil
                client_queue = @@query_hash[id].client_queue
                res = @@query_hash[id].single_resolver
                query = @@query_hash[id].query

                #  NOW RESEND OVER TCP!
                Thread.new {
                  res.send_async(query, client_queue, id, true)
                }
                sent = true
              end
            end
          }
          if !sent
            send_exception_to_client(e, socket, client_id)
          end

        else
          send_exception_to_client(e, socket, client_id)
        end
        return
      end

      if (ans!= nil)
        Dnsruby.log.debug{"#{ans}"}
        ans.answerfrom=(answerfrom)
        ans.answersize=(answersize)
        ans.answerip =(answerip)
      end
      return ans, buf
    end

    def handle_recvfrom_failure(socket, exception)
      #   No way to notify the client about this error, unless there was only one connection on the socket
      #  Not a problem, as there only will ever be one connection on the socket (Kaminsky attack mitigation)
      ids_for_socket = []
      @@mutex.synchronize{
        ids_for_socket = @@socket_hash[socket]
      }
      if (ids_for_socket.length == 1)
        answerfrom=nil
        @@mutex.synchronize{
          query_settings = @@query_hash[ids_for_socket[0]]
          answerfrom=query_settings.dest_server
        }
        send_exception_to_client(OtherResolvError.new("recvfrom failed from #{answerfrom}; #{exception}"), socket, ids_for_socket[0])
      else
        Dnsruby.log.fatal{"Recvfrom failed from #{socket}, no way to tell query id"}
      end
    end

    def get_client_id_from_answerfrom(socket, answerip, answerport)
      #  @TODO@ Can get rid of this, as there is only one query per socket
      client_id=nil
      #  Figure out client id from answerfrom
      @@mutex.synchronize{
        ids = @@socket_hash[socket]
        ids.each do |id|
          #  Does this id speak to this dest_server?
          query_settings = @@query_hash[id]
          if (answerip == query_settings.dest_server && answerport == query_settings.dest_port)
            #  We have a match
            client_id = id
            break
          end
        end
      }
      return client_id
    end

    def send_exception_to_client(err, socket, client_id, msg=nil)
      #  find the client response queue
      client_queue = nil
      @@mutex.synchronize {
        client_queue = @@query_hash[client_id].client_queue
      }
      remove_id(client_id)
      #       push_to_client(client_id, client_queue, msg, err)
      client_queue.push([client_id, Resolver::EventType::ERROR, msg, err])
      notify_queue_observers(client_queue, client_id)
    end

    def push_exception_to_select(client_id, client_queue, err, msg)
      @@mutex.synchronize{
        @@queued_exceptions.push([client_id, client_queue, err, msg])
      }
      #  Make sure select loop is running!
      if (@@select_thread && @@select_thread.alive?)
      else
        @@select_thread = Thread.new {
          do_select
        }
      end
    end

    def push_response_to_select(client_id, client_queue, msg, query, res)
      #  This needs to queue the response TO THE SELECT THREAD, which then needs
      #  to send it out from its normal loop.
      Dnsruby.log.debug{"Pushing response to client queue direct from resolver or validator"}
      @@mutex.synchronize{
        err = nil
        if (msg.rcode == RCode.NXDOMAIN)
          err = NXDomain.new
        end
        @@queued_responses.push([client_id, client_queue, msg, err, query, res])
      }
      #  Make sure select loop is running!
      if (@@select_thread && @@select_thread.alive?)
      else
        @@select_thread = Thread.new {
          do_select
        }
      end
    end

    def push_validation_response_to_select(client_id, client_queue, msg, err, query, res)
      #  This needs to queue the response TO THE SELECT THREAD, which then needs
      #  to send it out from its normal loop.
      Dnsruby.log.debug{"Pushing response to client queue direct from resolver or validator"}
      @@mutex.synchronize{
        @@queued_validation_responses.push([client_id, client_queue, msg, err, query, res])
      }
      #  Make sure select loop is running!
      if (@@select_thread && @@select_thread.alive?)
      else
        @@select_thread = Thread.new {
          do_select
        }
      end
    end

    def send_queued_exceptions
      exceptions = []
      @@mutex.synchronize{
        exceptions = @@queued_exceptions
        @@queued_exceptions = []
      }

      exceptions.each do |item|
        client_id, client_queue, err, msg = item
        #         push_to_client(client_id, client_queue, msg, err)
        client_queue.push([client_id, Resolver::EventType::ERROR, msg, err])
        notify_queue_observers(client_queue, client_id)
      end
    end

    def send_queued_responses
      responses = []
      @@mutex.synchronize{
        responses = @@queued_responses
        @@queued_responses = []
      }

      responses.each do |item|
        client_id, client_queue, msg, err, query, res = item
        #         push_to_client(client_id, client_queue, msg, err)
        client_queue.push([client_id, Resolver::EventType::RECEIVED, msg, err])
        notify_queue_observers(client_queue, client_id)
        #  Do we need to validate this? The response has come from the cache -
        #  validate it only if it has not been validated already
        #  So, if we need to validate it, send it to the validation thread
        #  Otherwise, send VALIDATED to the requester.
        if (((msg.security_level == Message::SecurityLevel.UNCHECKED) ||
                (msg.security_level == Message::SecurityLevel.INDETERMINATE)) &&
              (ValidatorThread.requires_validation?(query, msg, err, res)))
          validator = ValidatorThread.new(client_id, client_queue, msg, err, query ,self, res)
          validator.run
        else
          PacketSender.cache(query, msg) # The validator won't cache it, so we'd better do it now
          client_queue.push([client_id, Resolver::EventType::VALIDATED, msg, err])
          notify_queue_observers(client_queue, client_id)
        end
      end
    end

    def send_queued_validation_responses
      responses = []
      @@mutex.synchronize{
        responses = @@queued_validation_responses
        @@queued_validation_responses = []
      }

      responses.each do |item|
        client_id, client_queue, msg, err, query, res = item
        #         push_to_client(client_id, client_queue, msg, err)
        client_queue.push([client_id, Resolver::EventType::VALIDATED, msg, err])
        notify_queue_observers(client_queue, client_id)
      end
    end

    def push_to_client(client_id, client_queue, msg, err, query, res)
      #  @TODO@ Really need to let the client know that we have received a valid response!
      #  Can do that by calling notify_observers here, but with an identifier which
      #  defines the response to be a "Response received - validating. Please stop sending"
      #  type of response.
      client_queue.push([client_id, Resolver::EventType::RECEIVED, msg, err])
      notify_queue_observers(client_queue, client_id)

      if (!err || (err.instance_of?(NXDomain)))
        # 
        #  This method now needs to push the response to the validator,
        #  which will then take responsibility for delivering it to the client.
        #  The validator will need access to the queue observers -
        validator = ValidatorThread.new(client_id, client_queue, msg, err, query ,self, res)
        validator.run
        #       @@validator.add_to_queue([client_id, client_queue, msg, err, query, self, res])
      end
    end

    def add_observer(client_queue, observer)
      @@mutex.synchronize {
        @@observers[client_queue]=observer
        check_select_thread_synchronized # Is this really necessary? The client should start the thread by sending a query, really...
        if (!@@tick_observers.include?observer)
          @@tick_observers.push(observer)
        end
      }
    end

    def remove_observer(client_queue, observer)
      @@mutex.synchronize {
        if (@@observers[client_queue]==observer)
          #           @@observers.delete(observer)
          @@observers.delete(client_queue)
        else
          if (@@observers[client_queue] == nil)
          end
          Dnsruby.log.error{"remove_observer called with wrong observer for queue"}
          raise ArgumentError.new("remove_observer called with wrong observer for queue")
        end
        if (!@@observers.values.include?observer)
          @@tick_observers.delete(observer)
        end
      }
    end

    def notify_queue_observers(client_queue, client_query_id)
      #  If any observers are known for this query queue then notify them
      observer=nil
      @@mutex.synchronize {
        observer = @@observers[client_queue]
      }
      if (observer)
        observer.handle_queue_event(client_queue, client_query_id)
      end
    end

    def send_tick_to_observers
      #  If any observers are known then send them a tick
      tick_observers=nil
      @@mutex.synchronize {
        tick_observers = @@tick_observers
      }
      tick_observers.each do |observer|
        observer.tick
      end
    end
  end
end
