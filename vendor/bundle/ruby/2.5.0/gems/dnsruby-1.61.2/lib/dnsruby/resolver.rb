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
# require 'Dnsruby/resolver_register.rb'

require 'dnsruby/packet_sender'
require 'dnsruby/recursor'

module Dnsruby
  #  == Description
  #  Dnsruby::Resolver is a DNS stub resolver.
  #  This class performs queries with retries across multiple nameservers.
  #  The system configured resolvers are used by default.
  #
  #  The retry policy is a combination of the Net::DNS and dnsjava approach, and has the option of :
  #  * A total timeout for the query (defaults to 0, meaning "no total timeout")
  #  * A retransmission system that targets the namervers concurrently once the first query round is
  #   complete, but in which the total time per query round is split between the number of nameservers
  #   targetted for the first round. and total time for query round is doubled for each query round
  #
  #  Note that, if a total timeout is specified, then that will apply regardless of the retry policy
  #  (i.e. it may cut retries short).
  #
  #  Note also that these timeouts are distinct from the SingleResolver's packet_timeout
  #
  #  Timeouts apply to the initial query and response. If DNSSEC validation is to
  #  be performed, then additional queries may be required (these are performed automatically
  #  by Dnsruby). Each additional query will be performed with its own timeouts.
  #  So, even with a query_timeout of 5 seconds, a response which required extensive
  #  validation may take several times that long.
  #  (Future versions of Dnsruby may expose finer-grained events for client tracking of
  #  responses and validation)
  #
  #  == Methods
  #
  #  === Synchronous
  #  These methods raise an exception or return a response message with rcode==NOERROR
  #
  #  *  Dnsruby::Resolver#send_message(msg)
  #  *  Dnsruby::Resolver#query(name [, type [, klass]])
  #
  #    There are "!" versions of these two methods that return an array [response, error]
  #    instead of raising an error on failure.  They can be called as follows:
  #
  #    response, error = resolver.send_message!(...)
  #    response, error = resolver.query!(...)
  #
  #    If the request succeeds, response will contain the Dnsruby::Message response
  #    and error will be nil.
  #
  #    If the request fails, response will be nil and error will contain the error raised.
  #
  #  === Asynchronous
  #  These methods use a response queue to return the response and the error
  #
  #  *  Dnsruby::Resolver#send_async(msg, response_queue, query_id)
  #
  #  == Event Loop
  #  Dnsruby runs a pure Ruby event loop to handle I/O in a single thread.
  #  Support for EventMachine has been deprecated.
  class Resolver
    DefaultQueryTimeout = 0
    DefaultPacketTimeout = 5
    DefaultRetryTimes = 1
    DefaultRetryDelay = 5
    DefaultPipeLiningMaxQueries = 5
    DefaultPort = 53
    DefaultDnssec = false
    AbsoluteMinDnssecUdpSize = 1220
    MinDnssecUdpSize = 4096
    DefaultUDPSize = MinDnssecUdpSize

    class EventType
      RECEIVED = 0
      VALIDATED = 1 # @TODO@ Should be COMPLETE?
      ERROR = 2
    end

    #  The port to send queries to on the resolver
    attr_reader :port

    #  Should TCP be used as a transport rather than UDP?
    #  If use_tcp==true, then ONLY TCP will be used as a transport.
    attr_reader :use_tcp

    #  If tcp_pipelining==true, then we reuse the TCP connection
    attr_reader :tcp_pipelining

    # How many times (number of messages) to reuse the pipelining connection
    # before closing, :infinite for infinite number of requests per connection
    attr_reader :tcp_pipelining_max_queries

    #  If no_tcp==true, then ONLY UDP will be used as a transport.
    #  This should not generally be used, but is provided as a debugging aid.
    attr_reader :no_tcp


    attr_reader :tsig

    #  Should truncation be ignored?
    #  i.e. the TC bit is ignored and thus the resolver will not requery over TCP if TC is set
    attr_reader :ignore_truncation

    #  The source address to send queries from for IPv4
    attr_reader :src_address

    #  The source address to send queries from for IPv6
    attr_reader :src_address6

    #  Should the Recursion Desired bit be set?
    attr_reader :recurse

    #  The maximum UDP size to be used
    attr_reader :udp_size

    #  The current Config
    attr_reader :config

    #  Does this Resolver cache answers, and attempt to retrieve answer from the cache?
    attr_reader :do_caching

    #  The array of SingleResolvers used for sending query messages
    #     attr_accessor :single_resolvers # :nodoc:
    def single_resolvers=(s) # :nodoc:
      @configured = true
      #       @single_res_mutex.synchronize {
      @single_resolvers = s
      #       }
    end
    def single_resolvers # :nodoc:
      unless @configured
        add_config_nameservers
      end
      @single_resolvers
    end

    #  The timeout for any individual packet. This is the timeout used by SingleResolver
    attr_reader :packet_timeout

    #  Note that this timeout represents the total time a query may run for - multiple packets
    #  can be sent to multiple nameservers in this time.
    #  This is distinct from the SingleResolver per-packet timeout
    #  The query_timeout is not required - it will default to 0, which means "do not use query_timeout".
    #  If this is the case then the timeout will be dictated by the retry_times and retry_delay attributes
    attr_accessor :query_timeout

    #  The query will be tried across nameservers retry_times times, with a delay of retry_delay seconds
    #  between each retry. The first time round, retry_delay will be divided by the number of nameservers
    #  being targetted, and a new nameserver will be queried with the resultant delay.
    attr_accessor :retry_times, :retry_delay

    #  Use DNSSEC for this Resolver
    attr_reader :dnssec

    #  Defines whether validation is performed by default on this Resolver when the
    #  query method is called.
    #  Note that send_message and send_async expect a
    #  Message object to be passed in, which is already configured to the callers
    #  requirements.
    attr_accessor :do_validation

    #  Defines whether we will cache responses, or pass every request to the
    #  upstream resolver.  This is only really useful when querying authoritative
    #  servers (as the upstream recursive resolver is likely to cache)
    attr_accessor :do_caching

    #  --
    #  @TODO@ add load_balance? i.e. Target nameservers in a random, rather than pre-determined, order?
    #  This is best done when configuring the Resolver, as it will re-order servers based on their response times.
    #
    #  ++

    #  Query for a name. If a valid Message is received, then it is returned
    #  to the caller. Otherwise an exception (a Dnsruby::ResolvError or Dnsruby::ResolvTimeout) is raised.
    #
    #    require 'dnsruby'
    #    res = Dnsruby::Resolver.new
    #    response = res.query('example.com') # defaults to Types.A, Classes.IN
    #    response = res.query('example.com', Types.MX)
    #    response = res.query('208.77.188.166') # IPv4 address so PTR query will be made
    #    response = res.query('208.77.188.166', Types.PTR)
    def query(name, type=Types.A, klass=Classes.IN, set_cd=@dnssec)
      msg = Message.new
      msg.do_caching = @do_caching
      msg.header.rd = 1
      msg.add_question(name, type, klass)
      msg.do_validation = @do_validation
      if @dnssec
        msg.header.cd = set_cd # We do our own validation by default
      end
      send_message(msg)
    end

    #  Like query, but does not raise an error when an error occurs.
    #  Instead, it returns it.
    #  @return a 2 element array: [response, error]
    def query!(name, type=Types.A, klass=Classes.IN, set_cd=@dnssec)
      response = nil; error = nil
      begin
        response = query(name, type, klass, set_cd)
      rescue => e
        error = e
      end
      [response, error]
    end

    def query_no_validation_or_recursion(name, type=Types.A, klass=Classes.IN) # :nodoc: all
      msg = Message.new
      msg.do_caching = @do_caching
      msg.header.rd = false
      msg.do_validation = false
      msg.add_question(name, type, klass)
      if @dnssec
        msg.header.cd = true # We do our own validation by default
      end
      send_message(msg)
    end

    #  Send a message, and wait for the response. If a valid Message is received, then it is returned
    #  to the caller. Otherwise an exception (a Dnsruby::ResolvError or Dnsruby::ResolvTimeout) is raised.
    #
    #  send_async is called internally.
    #
    #  example :
    #
    #    require 'dnsruby'
    #    include Dnsruby
    #    res = Dnsruby::Resolver.new
    #    begin
    #    response = res.send_message(Message.new('example.com', Types.MX))
    #    rescue ResolvError
    #      # ...
    #    rescue ResolvTimeout
    #      # ...
    #    end
    def send_message(message)
      Dnsruby.log.debug{'Resolver : sending message'}
      q = Queue.new
      send_async(message, q)

      _id, result, error = q.pop

      if error
        error.response = result if error.is_a?(ResolvError)
        raise error
      else
        result
      end
    end

    #  Like send_message, but does not raise an error when an error occurs.
    #  Instead, it returns it.
    #  @return a 2 element array: [response, error]
    def send_message!(message)
      response = nil; error = nil
      begin
        response = send_message(message)
      rescue => e
        error = e
      end
      [response, error]
    end

    # Sends a message with send_plain_message.
    # Effectively a wrapper around send_plain_message, but adds
    # the ability to configure whether an error will be raised
    # or returned if it occurs.
    #
    # @param message the message to send to the DNS server
    # @param error_strategy :return to return [response, error] (default),
    #                       :raise to return response only, or raise an error if one occurs
    def query_raw(message, error_strategy = :return)

      unless [:return, :raise].include?(error_strategy)
        raise ArgumentError.new('error_strategy should be one of [:return, :raise].')
      end

      response, error = send_plain_message(message)

      if error_strategy == :return
        [response, error]
      else
        raise error if error
        response
      end
    end

    #  This method takes a Message (supplied by the client), and sends it to
    #  the configured nameservers. No changes are made to the Message before it
    #  is sent (TSIG signatures will be applied if configured on the Resolver).
    #  Retries are handled as the Resolver is configured to do.
    #  Incoming responses to the query are not cached or validated (although TCP
    #  fallback will be performed if the TC bit is set and the (Single)Resolver has
    #  ignore_truncation set to false).
    #  Note that the Message is left untouched - this means that no OPT records are
    #  added, even if the UDP transport for the server is specified at more than 512
    #  bytes. If it is desired to use EDNS for this packet, then you should call
    #  the Dnsruby::PacketSender#prepare_for_dnssec(msg), or
    #  Dnsruby::PacketSender#add_opt_rr(msg)
    #  The return value from this method is the [response, error] tuple. Either of
    #  these values may be nil - it is up to the client to check.
    #
    #  example :
    #
    #    require 'dnsruby'
    #    include Dnsruby
    #    res = Dnsruby::Resolver.new
    #    response, error = res.send_plain_message(Message.new('example.com', Types.MX))
    #    if error
    #      print "Error returned : #{error}\n"
    #    else
    #      process_response(response)
    #    end
    def send_plain_message(message)
      Dnsruby::TheLog.debug('Resolver : send_plain_message')
      message.do_caching = false
      message.do_validation = false
      message.send_raw = true
      q = Queue.new
      send_async(message, q)
      _id, result, error = q.pop
      error.response = result if !error.nil? && error.is_a?(ResolvError)
      [result, error]
    end


    #  Asynchronously send a Message to the server. The send can be done using just
    #  Dnsruby. Support for EventMachine has been deprecated.
    #
    #  == Dnsruby pure Ruby event loop :
    #
    #  A client_queue is supplied by the client,
    #  along with an optional client_query_id to identify the response. The client_query_id
    #  is generated, if not supplied, and returned to the client.
    #  When the response is known,
    #  a tuple of (query_id, response_message, exception) will be added to the client_queue.
    #
    #  The query is sent synchronously in the caller's thread. The select thread is then used to
    #  listen for and process the response (up to pushing it to the client_queue). The client thread
    #  is then used to retrieve the response and deal with it.
    #
    #  Takes :
    #
    #  * msg - the message to send
    #  * client_queue - a Queue to push the response to, when it arrives
    #  * client_query_id - an optional ID to identify the query to the client
    #  * use_tcp - whether to use only TCP (defaults to SingleResolver.use_tcp)
    #
    #  Returns :
    #
    #  * client_query_id - to identify the query response to the client. This ID is
    #  generated if it is not passed in by the client
    #
    #  === Example invocations :
    #
    #     id = res.send_async(msg, queue)
    #     NOT SUPPORTED : id = res.send_async(msg, queue, use_tcp)
    #     id = res.send_async(msg, queue, id)
    #     id = res.send_async(msg, queue, id, use_tcp)
    #
    #  === Example code :
    #
    #    require 'dnsruby'
    #    res = Dnsruby::Resolver.newsend
    #    query_id = 10 # can be any object you like
    #    query_queue = Queue.new
    #    res.send_async(Message.new('example.com', Types.MX),  query_queue, query_id)
    #    query_id_2 = res.send_async(Message.new('example.com', Types.A), query_queue)
    #    # ...do a load of other stuff here...
    #    2.times do
    #      response_id, response, exception = query_queue.pop
    #      # You can check the ID to see which query has been answered
    #      if exception == nil
    #          # deal with good response
    #      else
    #          # deal with problem
    #      end
    #    end
    #
    def send_async(msg, client_queue, client_query_id = nil)
      unless @configured
        add_config_nameservers
      end
      #       @single_res_mutex.synchronize {
      unless @resolver_ruby # @TODO@ Synchronize this?
        @resolver_ruby = ResolverRuby.new(self)
      end
      #       }
      client_query_id = @resolver_ruby.send_async(msg, client_queue, client_query_id)
      if @single_resolvers.length == 0
        Thread.start {
          sleep(@query_timeout == 0 ? 1 : @query_timeout)
          client_queue.push([client_query_id, nil, ResolvTimeout.new('Query timed out - no nameservers configured')])
        }
      end
      client_query_id
    end

    #  Close the Resolver. Unfinished queries are terminated with OtherResolvError.
    def close
      @resolver_ruby.close if @resolver_ruby
    end

    #  Create a new Resolver object. If no parameters are passed in, then the default
    #  system configuration will be used. Otherwise, a Hash may be passed in with the
    #  following optional elements :
    #
    #
    #  * :port
    #  * :use_tcp
    #  * :tsig
    #  * :ignore_truncation
    #  * :src_address
    #  * :src_address6
    #  * :src_port
    #  * :recurse
    #  * :udp_size
    #  * :config_info - see Config
    #  * :nameserver - can be either a String or an array of Strings
    #  * :packet_timeout
    #  * :query_timeout
    #  * :retry_times
    #  * :retry_delay
    #  * :do_caching
    #  * :tcp_pipelining
    #  * :tcp_pipelining_max_queries - can be a number or :infinite symbol
    def initialize(*args)
      #  @TODO@ Should we allow :namesver to be an RRSet of NS records? Would then need to randomly order them?
      @resolver_ruby = nil
      @src_address = nil
      @src_address6 = nil
      @single_res_mutex = Mutex.new
      @configured = false
      @do_caching = true
      @config = Config.new()
      reset_attributes

      #  Process args
      if args.length == 1
        if args[0].class == Hash
          args[0].keys.each do |key|
            begin
              if key == :config_info
                @config.set_config_info(args[0][:config_info])
              elsif key == :nameserver
                set_config_nameserver(args[0][:nameserver])
              elsif key == :nameservers
                set_config_nameserver(args[0][:nameservers])
              else
                send(key.to_s + '=', args[0][key])
              end
            rescue Exception => e
              Dnsruby.log.error{"Argument #{key} not valid : #{e}\n"}
            end
          end
        elsif args[0].class == String
          set_config_nameserver(args[0])
        elsif args[0].class == Config
          #  also accepts a Config object from Dnsruby::Resolv
          @config = args[0]
        end
      else
        #  Anything to do?
      end
      update
    end

    def add_config_nameservers # :nodoc: all
      unless @configured
        @config.get_ready
      end
      @configured = true
      @single_res_mutex.synchronize {
        #  Add the Config nameservers
        @config.nameserver.each do |ns|
          res = PacketSender.new({
              server:             ns,
              port:               @port,
              dnssec:             @dnssec,
              use_tcp:            @use_tcp,
              no_tcp:             @no_tcp,
              tcp_pipelining:     @tcp_pipelining,
              tcp_pipelining_max_queries: @tcp_pipelining_max_queries,
              packet_timeout:     @packet_timeout,
              tsig:               @tsig,
              ignore_truncation:  @ignore_truncation,
              src_address:        @src_address,
              src_address6:       @src_address6,
              src_port:           @src_port,
              recurse:            @recurse,
              udp_size:           @udp_size})
          @single_resolvers.push(res) if res
        end
      }
    end

    def set_config_nameserver(n)
      #  @TODO@ Should we allow NS RRSet here? If so, then .sort_by {rand}
      @config.get_ready unless @configured
      @configured = true

      @config.nameserver = n.kind_of?(String) ? [n] : n
      add_config_nameservers
    end

    def reset_attributes # :nodoc: all
      @resolver_ruby.reset_attributes if @resolver_ruby

      #  Attributes

      #  do_validation tells the Resolver whether to try to validate the response
      #  with DNSSEC. This should work for NSEC-signed domains, but NSEC3
      #  validation is not currently supported. This attribute now defaults to
      #  false. Please let me know if you require NSEC3 validation.
      @do_validation = false
      @query_timeout = DefaultQueryTimeout
      @retry_delay = DefaultRetryDelay
      @retry_times = DefaultRetryTimes
      @packet_timeout = DefaultPacketTimeout
      @port = DefaultPort
      @udp_size = DefaultUDPSize
      @dnssec = DefaultDnssec
      @do_caching= true
      @use_tcp = false
      @no_tcp = false
      @tcp_pipelining = false
      @tcp_pipelining_max_queries = DefaultPipeLiningMaxQueries
      @tsig = nil
      @ignore_truncation = false
      @config = Config.new()
      @src_address = nil
      @src_address6 = nil
      @src_port = [0]
      @recurse = true
      @single_res_mutex.synchronize {
        @single_resolvers=[]
      }
      @configured = false
    end

    def update # :nodoc: all
      #  Update any resolvers we have with the latest config
      @single_res_mutex.synchronize do
        @single_resolvers.delete(nil) # Just in case...
        @single_resolvers.each { |res| update_internal_res(res) }
      end
    end

    #     # Add a new SingleResolver to the list of resolvers this Resolver object will
    #     # query.
    #     def add_resolver(internal) # :nodoc:
    #       # @TODO@ Make a new PacketSender from this SingleResolver!!
    #       @single_resolvers.push(internal)
    #     end

    def add_server(server)# :nodoc:
      @configured = true
      res = PacketSender.new(server)
      log_and_raise("Can't create server #{server}", ArgumentError) unless res
      update_internal_res(res)
      @single_res_mutex.synchronize { @single_resolvers.push(res) }
    end

    def update_internal_res(res)
      [:port, :use_tcp, :no_tcp, :tcp_pipelining, :tcp_pipelining_max_queries, :tsig, :ignore_truncation, :packet_timeout,
        :src_address, :src_address6, :src_port, :recurse,
        :udp_size, :dnssec].each do |param|

        res.send(param.to_s + '=', instance_variable_get('@' + param.to_s))
      end
    end

    def nameservers=(ns)
      self.nameserver=(ns)
    end

    def nameserver=(n)
      @configured = true
      @single_res_mutex.synchronize { @single_resolvers=[] }
      set_config_nameserver(n)
      add_config_nameservers
    end

    #  --
    #  @TODO@ Should really auto-generate these methods.
    #  Also, any way to tie them up with SingleResolver RDoc?
    #  ++

    def packet_timeout=(t)
      @packet_timeout = t
      update
    end

    #  The source port to send queries from
    #  Returns either a single Integer or an Array
    #  e.g. '0', or '[60001, 60002, 60007]'
    #
    #  Defaults to 0 - random port
    def src_port
      @src_port.length == 1 ? @src_port[0] : @src_port
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
      if Resolver.check_port(p)
        @src_port = Resolver.get_ports_from(p)
        update
      end
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
      if Resolver.check_port(p, @src_port)
        a = Resolver.get_ports_from(p)
        a.each do |x|
          if (@src_port.length > 0) && (x == 0)
            log_and_raise("src_port of 0 only allowed as only src_port value (currently #{@src_port.length} values",
                ArgumentError)
          end
          @src_port.push(x)
        end
      end
      update
    end

    def Resolver.check_port(p, src_port=[])
      unless p.is_a?(Integer)
        tmp_src_ports = Array.new(src_port)
        p.each do |x|
          unless Resolver.check_port(x, tmp_src_ports)
            return false
          end
          tmp_src_ports.push(x)
        end
        return true
      end
      if Resolver.port_in_range(p)
        return ! ((p == 0) && (src_port.length > 0))
      else
        Dnsruby.log.error("Illegal port (#{p})")
        log_and_raise("Illegal port #{p}", ArgumentError)
      end
    end

    def Resolver.port_in_range(p)
      (p == 0) || ((p >= 50000) && (p <= 65535))
    end

    def Resolver.get_ports_from(p)
      a = []
      if p.is_a?(Integer)
        a = [p]
      else
        p.each do |x|
          a.push(x)
        end
      end
      a
    end

    def tcp_pipelining=(on)
      @tcp_pipelining = on
      update
    end

    def tcp_pipelining_max_queries=(max)
      @tcp_pipelining_max_queries = max
      update
    end

    def use_tcp=(on)
      @use_tcp = on
      update
    end

    def no_tcp=(on)
      @no_tcp=on
      update
    end

    #  Sets the TSIG to sign outgoing messages with.
    #  Pass in either a Dnsruby::RR::TSIG, or a key_name and key (or just a key)
    #  Pass in nil to stop tsig signing.
    #  * res.tsig=(tsig_rr)
    #  * res.tsig=(key_name, key) # defaults to hmac-md5
    #  * res.tsig=(key_name, key, alg) # e.g. alg = 'hmac-sha1'
    #  * res.tsig=nil # Stop the resolver from signing
    def tsig=(t)
      @tsig = t
      update
    end


    protected
    def Resolver.create_tsig_options(name, key, algorithm = nil)
        options = {
          type:  Types.TSIG,
          klass: Classes.ANY,
          name:  name,
          key:   key
      }
      options[:algorithm] = algorithm if algorithm
      options
    end


    public
    def Resolver.get_tsig(args)

      tsig = nil

      if args.length == 1
        if args[0]
          if args[0].instance_of?(RR::TSIG)
            tsig = args[0]
          elsif args[0].instance_of?(Array)
            tsig = RR.new_from_hash(create_tsig_options(*args[0]))
          end
        else
          #           Dnsruby.log.debug{'TSIG signing switched off'}
          return nil
        end
      else
        tsig = RR.new_from_hash(create_tsig_options(args))
      end
      Dnsruby.log.info{"TSIG signing now using #{tsig.name}, key=#{tsig.key}"}
      tsig
    end


    def ignore_truncation=(on)
      @ignore_truncation = on
      update
    end

    def src_address=(a)
      @src_address = a
      update
    end

    def src_address6=(a)
      @src_address6 = a
      update
    end

    def port=(a)
      @port = a
      update
    end

    def persistent_tcp=(on)
      @persistent_tcp = on
      update
    end

    def persistent_udp=(on)
      @persistent_udp = on
      update
    end

    def do_caching=(on)
      @do_caching=on
      update
    end

    def recurse=(a)
      @recurse = a
      update
    end

    def dnssec=(d)
      @dnssec = d
      if d
        #  Set the UDP size (RFC 4035 section 4.1)
        if @udp_size < MinDnssecUdpSize
          self.udp_size = MinDnssecUdpSize
        end
      end
      update
    end

    def udp_size=(s)
      @udp_size = s
      update
    end

    def single_res_mutex # :nodoc: all
      @single_res_mutex
    end

    def generate_timeouts(base=0) # :nodoc: all
      #  These should be be pegged to the single_resolver they are targetting :
      #   e.g. timeouts[timeout1]=nameserver
      timeouts = {}
      retry_delay = @retry_delay
      #       @single_res_mutex.synchronize {
      @retry_times.times do |retry_count|
        if retry_count > 0
          retry_delay *= 2
        end

        @single_resolvers.delete(nil) # Just in case...
        @single_resolvers.each_index do |i|
          res = @single_resolvers[i]
          offset = (i * @retry_delay.to_f / @single_resolvers.length)
          if retry_count == 0
            timeouts[base + offset]=[res, retry_count]
          else
            if timeouts.has_key?(base + retry_delay + offset)
              log_and_raise('Duplicate timeout key!')
            end
            timeouts[base + retry_delay + offset]=[res, retry_count]
          end
        end
      end
      #       }
      timeouts
    end
  end


  #  This class implements the I/O using pure Ruby, with no dependencies.
  #  Support for EventMachine has been deprecated.
  class ResolverRuby # :nodoc: all
    def initialize(parent)
      reset_attributes
      @parent=parent
    end
    def reset_attributes # :nodoc: all
      #  data structures
      #       @mutex=Mutex.new
      @query_list = {}
      @timeouts = {}
    end
    def send_async(msg, client_queue, client_query_id=nil)
      #  This is the whole point of the Resolver class.
      #  We want to use multiple SingleResolvers to run a query.
      #  So we kick off a system with select_thread where we send
      #  a query with a queue, but log ourselves as observers for that
      #  queue. When a new response is pushed on to the queue, then the
      #  select thread will call this class' handler method IN THAT THREAD.
      #  When the final response is known, this class then sticks it in
      #  to the client queue.

      q = Queue.new
      if client_query_id.nil?
        client_query_id = Time.now + rand(10000)
      end

      unless client_queue.kind_of?(Queue)
        log_and_raise('Wrong type for client_queue in Resolver# send_async')
        #  @TODO@ Handle different queue tuples - push this to generic send_error method
        client_queue.push([client_query_id, ArgumentError.new('Wrong type of client_queue passed to Dnsruby::Resolver# send_async - should have been Queue, was #{client_queue.class}')])
        return
      end

      unless msg.kind_of?Message
        Dnsruby.log.error{'Wrong type for msg in Resolver# send_async'}
        #  @TODO@ Handle different queue tuples - push this to generic send_error method
        client_queue.push([client_query_id, ArgumentError.new("Wrong type of msg passed to Dnsruby::Resolver# send_async - should have been Message, was #{msg.class}")])
        return
      end

      begin
        msg.encode
      rescue EncodeError => err
        Dnsruby.log.error { "Can't encode " + msg.to_s + " : #{err}" }
        client_queue.push([client_query_id, err])
        return
      end

      tick_needed = false
      #  add to our data structures
      #       @mutex.synchronize{
      @parent.single_res_mutex.synchronize {
        tick_needed = true if @query_list.empty?
        if @query_list.has_key?(client_query_id)
          Dnsruby.log.error("Duplicate query id requested (#{client_query_id}")
          #  @TODO@ Handle different queue tuples - push this to generic send_error method
          client_queue.push([client_query_id, ArgumentError.new('Client query ID already in use')])
          return
        end
        outstanding = []
        @query_list[client_query_id]=[msg, client_queue, q, outstanding]

        query_timeout = Time.now + @parent.query_timeout
        if @parent.query_timeout == 0
          query_timeout = Time.now + 31536000 # a year from now
        end
        @timeouts[client_query_id] = [query_timeout, generate_timeouts]
      }

      #  Now do querying stuff using SingleResolver
      #  All this will be handled by the tick method (if we have 0 as the first timeout)
      st = SelectThread.instance
      st.add_observer(q, self)
      tick if tick_needed
      client_query_id
    end

    def generate_timeouts # :nodoc: all
      #  Create the timeouts for the query from the retry_times and retry_delay attributes.
      #  These are created at the same time in case the parameters change during the life of the query.
      #
      #  These should be absolute, rather than relative
      #  The first value should be Time.now[
      @parent.generate_timeouts(Time.now)
    end

    #  Close the Resolver. Unfinished queries are terminated with OtherResolvError.
    def close
      #       @mutex.synchronize {
      @parent.single_res_mutex.synchronize {
        @query_list.each do |client_query_id, values|
         _msg, client_queue, q, _outstanding = values
          send_result_and_stop_querying(client_queue, client_query_id, q, nil,
              OtherResolvError.new('Resolver closing!'))
        end
      }
    end

    #  MUST BE CALLED IN A SYNCHRONIZED BLOCK!
    #
    #  Send the result back to the client, and close the socket for that query by removing
    #  the query from the select thread.
    def send_result_and_stop_querying(client_queue, client_query_id, select_queue, msg, error) # :nodoc: all
      stop_querying(client_query_id)
      send_result(client_queue, client_query_id, select_queue, msg, error)
    end

    #  MUST BE CALLED IN A SYNCHRONIZED BLOCK!
    #
    #  Stops send any more packets for a client-level query
    def stop_querying(client_query_id) # :nodoc: all
      @timeouts.delete(client_query_id)
    end

    #  MUST BE CALLED IN A SYNCHRONIZED BLOCK!
    #
    #  Sends the result to the client's queue, and removes the queue observer from the select thread
    def send_result(client_queue, client_query_id, select_queue, msg, error) # :nodoc: all
      stop_querying(client_query_id)  # @TODO@ !
      #  We might still get some callbacks, which we should ignore
      st = SelectThread.instance
      st.remove_observer(select_queue, self)
      #       @mutex.synchronize{
      #  Remove the query from all of the data structures
      @query_list.delete(client_query_id)
      #       }
      #  Return the response to the client
      client_queue.push([client_query_id, msg, error])
    end

    #  This method is called twice a second from the select loop, in the select thread.
    #  It should arguably be called from another worker thread... (which also handles the queue)
    #  Each tick, we check if any timeouts have occurred. If so, we take the appropriate action :
    #  Return a timeout to the client, or send a new query
    def tick # :nodoc: all
      #  Handle the tick
      #  Do we have any retries due to be sent yet?
      #       @mutex.synchronize{
      @parent.single_res_mutex.synchronize {
        time_now = Time.now
        @timeouts.keys.each do |client_query_id|
          msg, client_queue, select_queue, outstanding = @query_list[client_query_id]
          query_timeout, timeouts = @timeouts[client_query_id]
          if query_timeout < Time.now
            #  Time the query out
            send_result_and_stop_querying(client_queue, client_query_id, select_queue, nil,
                ResolvTimeout.new('Query timed out'))
            next
          end
          timeouts_done = []
          timeouts.keys.sort.each do |timeout|
            if timeout < time_now
              #  Send the next query
              res, retry_count = timeouts[timeout]
              id = [res, msg, client_query_id, retry_count]
              Dnsruby.log.debug("Sending msg to #{res.server}")
              #  We should keep a list of the queries which are outstanding
              outstanding.push(id)
              timeouts_done.push(timeout)
              timeouts.delete(timeout)

              #  Pick a new QID here @TODO@ !!!
              #               msg.header.id = rand(65535);
              #               print "New query : #{new_msg}\n"
              res.send_async(msg, select_queue, id)
            else
              break
            end
          end
          timeouts_done.each { |t| timeouts.delete(t) }
        end
      }
    end

    #  This method is called by the SelectThread (in the select thread) when the queue has a new item on it.
    #  The queue interface is used to separate producer/consumer threads, but we're using it here in one thread.
    #  It's probably a good idea to create a new "worker thread" to take items from the select thread queue and
    #  call this method in the worker thread.
    #
    def handle_queue_event(queue, id) # :nodoc: all
      #  Time to process a new queue event.
      #  If we get a callback for an ID we don't know about, don't worry -
      #  just ignore it. It may be for a query we've already completed.
      #
      #  So, get the next response from the queue (presuming there is one!)
      #
      #  @TODO@ Tick could poll the queue and then call this method if needed - no need for observer interface.
      #  @TODO@ Currently, tick and handle_queue_event called from select_thread - could have thread chuck events in to tick_queue. But then, clients would have to call in on other thread!
      #
      #  So - two types of response :
      #  1) we've got a coherent response (or error) - stop sending more packets for that query!
      #  2) we've validated the response - it's ready to be sent to the client
      #
      #  so need two more methods :
      #   handleValidationResponse : basically calls send_result_and_stop_querying and
      #   handleValidationError : does the same as handleValidationResponse, but for errors
      #  can leave handleError alone
      #  but need to change handleResponse to stop sending, rather than send_result_and_stop_querying.
      #
      #  @TODO@ Also, we could really do with a MaxValidationTimeout - if validation not OK within
      #  this time, then raise Timeout (and stop validation)?
      #
      #  @TODO@ Also, should there be some facility to stop validator following same chain
      #  concurrently?
      #
      #  @TODO@ Also, should have option to speak only to configured resolvers (not follow authoritative chain)
      #
      if queue.empty?
        log_and_raise('Severe internal error - Queue empty in handle_queue_event')
      end
      event_id, event_type, response, error = queue.pop
      #  We should remove this packet from the list of outstanding packets for this query
      _resolver, _msg, client_query_id, _retry_count = id
      if id != event_id
        log_and_raise("Serious internal error!! #{id} expected, #{event_id} received")
      end
      #       @mutex.synchronize{
      @parent.single_res_mutex.synchronize {
        if @query_list[client_query_id] == nil
          #           print "Dead query response - ignoring\n"
          Dnsruby.log.debug{'Ignoring response for dead query'}
          return
        end
        _msg, _client_queue, _select_queue, outstanding = @query_list[client_query_id]
        if event_type == Resolver::EventType::RECEIVED ||
              event_type == Resolver::EventType::ERROR
          unless outstanding.include?(id)
            log_and_raise("Query id not on outstanding list! #{outstanding.length} items. #{id} not on #{outstanding}")
          end
          outstanding.delete(id)
        end
        #       }
        if event_type == Resolver::EventType::RECEIVED
          #       if (event.kind_of?(Exception))
          if error
            handle_error_response(queue, event_id, error, response)
          else # if event.kind_of?(Message)
            handle_response(queue, event_id, response)
            #       else
            #         Dnsruby.log.error('Random object #{event.class} returned through queue to Resolver')
          end
        elsif event_type == Resolver::EventType::VALIDATED
          if error
            handle_validation_error(queue, event_id, error, response)
          else
            handle_validation_response(queue, event_id, response)
          end
        elsif event_type == Resolver::EventType::ERROR
          handle_error_response(queue, event_id, error, response)
        else
          #           print "ERROR - UNKNOWN EVENT TYPE IN RESOLVER : #{event_type}\n"
          TheLog.error("ERROR - UNKNOWN EVENT TYPE IN RESOLVER : #{event_type}")
        end
      }
    end

    def handle_error_response(select_queue, query_id, error, response) # :nodoc: all
      #  Handle an error
      #       @mutex.synchronize{
      Dnsruby.log.debug{"handling error #{error.class}, #{error}"}
      #  Check what sort of error it was :
      resolver, _msg, client_query_id, _retry_count = query_id
      _msg, client_queue, select_queue, outstanding = @query_list[client_query_id]
      if error.kind_of?(ResolvTimeout)
        #    - if it was a timeout, then check which number it was, and how many retries are expected on that server
        #        - if it was the last retry, on the last server, then return a timeout to the client (and clean up)
        #        - otherwise, continue
        #  Do we have any more packets to send to this resolver?

        decrement_resolver_priority(resolver)
        timeouts = @timeouts[client_query_id]
        if outstanding.empty? && timeouts && timeouts[1].values.empty?
          Dnsruby.log.debug{'Sending timeout to client'}
          send_result_and_stop_querying(client_queue, client_query_id, select_queue, response, error)
        end
      elsif error.kind_of?(NXDomain)
        #    - if it was an NXDomain, then return that to the client, and stop all new queries (and clean up)
        #         send_result_and_stop_querying(client_queue, client_query_id, select_queue, response, error)
        increment_resolver_priority(resolver) unless response.cached
        stop_querying(client_query_id)
        #  @TODO@ Does the client want notified at this point?
      elsif error.kind_of?(EncodeError)
        Dnsruby.log.debug{'Encode error - sending to client'}
        send_result_and_stop_querying(client_queue, client_query_id, select_queue, response, error)
      else
        #    - if it was any other error, then remove that server from the list for that query
        #    If a Too Many Open Files error, then don't remove, but let retry work.
        timeouts = @timeouts[client_query_id]
        unless error.to_s =~ /Errno::EMFILE/
          Dnsruby.log.debug{"Removing #{resolver.server} from resolver list for this query"}
          if timeouts
            timeouts[1].each do |key, value|
              res = value[0]
              if res == resolver
                timeouts[1].delete(key)
              end
            end
          end
          #  Also stick it to the back of the list for future queries
          demote_resolver(resolver)
        else
          Dnsruby.log.debug("NOT Removing #{resolver.server} due to Errno::EMFILE")
        end
        #         - if it was the last server, then return an error to the client (and clean up)
        if outstanding.empty? && ((!timeouts) || (timeouts && timeouts[1].values.empty?))
          #           if outstanding.empty?
          Dnsruby.log.debug{'Sending error to client'}
          send_result_and_stop_querying(client_queue, client_query_id, select_queue, response, error)
        end
      end
      #  @TODO@ If we're still sending packets for this query, but none are outstanding, then
      #  jumpstart the next query?
      #       }
    end

    #  TO BE CALLED IN A SYNCHRONIZED BLOCK
    def increment_resolver_priority(res)
      TheLog.debug("Incrementing resolver priority for #{res.server}\n")
      #       @parent.single_res_mutex.synchronize {
      index = @parent.single_resolvers.index(res)
      if index > 0
        @parent.single_resolvers.delete(res)
        @parent.single_resolvers.insert(index-1,res)
      end
      #       }
    end

    #  TO BE CALLED IN A SYNCHRONIZED BLOCK
    def decrement_resolver_priority(res)
      TheLog.debug("Decrementing resolver priority for #{res.server}\n")
      #       @parent.single_res_mutex.synchronize {
      index = @parent.single_resolvers.index(res)
      if index < @parent.single_resolvers.length
        @parent.single_resolvers.delete(res)
        @parent.single_resolvers.insert(index+1,res)
      end
      #       }
    end

    #  TO BE CALLED IN A SYNCHRONIZED BLOCK
    def demote_resolver(res)
      TheLog.debug("Demoting resolver priority for #{res.server} to bottom\n")
      #       @parent.single_res_mutex.synchronize {
      @parent.single_resolvers.delete(res)
      @parent.single_resolvers.push(res)
      #       }
    end

    def handle_response(select_queue, query_id, response) # :nodoc: all
      #  Handle a good response
      #  Should also stick resolver more to the front of the list for future queries
      Dnsruby.log.debug('Handling good response')
      resolver, _msg, client_query_id, _retry_count = query_id
      increment_resolver_priority(resolver) unless response.cached
      #       @mutex.synchronize{
      _query, _client_queue, s_queue, _outstanding = @query_list[client_query_id]
      if s_queue != select_queue
        log_and_raise("Serious internal error : expected select queue #{s_queue}, got #{select_queue}")
      end
      stop_querying(client_query_id)
      #  @TODO@ Does the client want notified at this point?
      #         client_queue.push([client_query_id, Resolver::EventType::RECEIVED, msg, nil])
      #       }
    end

    def handle_validation_response(select_queue, query_id, response) # :nodoc: all
      _resolver, _msg, client_query_id, _retry_count = query_id
      #       @mutex.synchronize {
      _query, client_queue, s_queue, _outstanding = @query_list[client_query_id]
      if s_queue != select_queue
        log_and_raise("Serious internal error : expected select queue #{s_queue}, got #{select_queue}")
      end
      if response.rcode == RCode.NXDOMAIN
        send_result(client_queue, client_query_id, select_queue, response, NXDomain.new)
      else
        #  @TODO@ Was there an error validating? Should we raise an exception for certain security levels?
        #  This should be configurable by the client.
        send_result(client_queue, client_query_id, select_queue, response, nil)
        #       }
      end
    end

    def handle_validation_error(select_queue, query_id, error, response)
      _resolver, _msg, client_query_id, _retry_count = query_id
      _query, client_queue, s_queue, _outstanding = @query_list[client_query_id]
      if s_queue != select_queue
        log_and_raise("Serious internal error : expected select queue #{s_queue}, got #{select_queue}")
      end
      #       For some errors, we immediately send result. For others, should we retry?
      #       Either :
      #                 handle_error_response(queue, event_id, error, response)
      #                 Or:
      send_result(client_queue, client_query_id, select_queue, response, error)
      #
      #
    end
  end
end
require 'dnsruby/single_resolver'
