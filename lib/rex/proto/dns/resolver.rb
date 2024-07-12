# -*- coding: binary -*-

require 'net/dns/resolver'
require 'dnsruby'

module Rex
module Proto
module DNS

  ##
  # Provides Rex::Sockets compatible version of Net::DNS::Resolver
  # Modified to work with Dnsruby::Messages, their resolvers are too heavy
  ##
  class Resolver < Net::DNS::Resolver

    Defaults = {
      :config_file => nil,
      :log_file => File::NULL, # formerly $stdout, should be tied in with our loggers
      :port => 53,
      :searchlist => [],
      :nameservers => [],
      :domain => "",
      :source_port => 0,
      :source_address => IPAddr.new("0.0.0.0"),
      :retry_interval => 5,
      :retry_number => 4,
      :recursive => true,
      :defname => true,
      :dns_search => true,
      :use_tcp => false,
      :ignore_truncated => false,
      :packet_size => 512,
      :tcp_timeout => TcpTimeout.new(5),
      :udp_timeout => UdpTimeout.new(5),
      :context => {},
      :comm => nil,
      :static_hosts => {}
    }

    attr_accessor :context, :comm, :static_hostnames
    #
    # Provide override for initializer to use local Defaults constant
    #
    # @param config [Hash] Configuration options as consumed by parent class
    def initialize(config = {})
      raise ResolverArgumentError, "Argument has to be Hash" unless config.kind_of? Hash
      # config.key_downcase!
      @config = Defaults.merge config
      @config[:config_file] ||= self.class.default_config_file
      @raw = false
      # New logger facility
      @logger = Logger.new(@config[:log_file])
      @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN

      #------------------------------------------------------------
      # Resolver configuration will be set in order from:
      # 1) initialize arguments
      # 2) ENV variables
      # 3) config file
      # 4) defaults (and /etc/resolv.conf for config)
      #------------------------------------------------------------

      #------------------------------------------------------------
      # Parsing config file
      #------------------------------------------------------------
      parse_config_file

      #------------------------------------------------------------
      # Parsing ENV variables
      #------------------------------------------------------------
      parse_environment_variables

      #------------------------------------------------------------
      # Parsing arguments
      #------------------------------------------------------------
      comm = config.delete(:comm)
      context = config.delete(:context)
      static_hosts = config.delete(:static_hosts)
      config.each do |key,val|
        next if key == :log_file or key == :config_file
        begin
          eval "self.#{key.to_s} = val"
        rescue NoMethodError
          raise ResolverArgumentError, "Option #{key} not valid"
        end
      end

      self.static_hostnames = StaticHostnames.new(hostnames: static_hosts)
      begin
        self.static_hostnames.parse_hosts_file
      rescue StandardError => e
        @logger.error 'Failed to parse the hosts file, ignoring it'
        # if the hosts file is corrupted, just use a default instance with any specified hostnames
        self.static_hostnames = StaticHostnames.new(hostnames: static_hosts)
      end
    end
    #
    # Provides current proxy setting if configured
    #
    # @return [String] Current proxy configuration
    def proxies
      @config[:proxies].inspect if @config[:proxies]
    end

    #
    # Configure proxy setting and additional timeout
    #
    # @param prox [String] SOCKS proxy connection string
    # @param timeout_added [Fixnum] Added TCP timeout to account for proxy
    def proxies=(prox, timeout_added = 250)
      return if prox.nil?
      if prox.is_a?(String) and prox.strip =~ /^socks/i
        @config[:proxies] = prox.strip
        @config[:use_tcp] = true
        self.tcp_timeout = self.tcp_timeout.to_s.to_i + timeout_added
        @logger.info "SOCKS proxy set, using TCP, increasing timeout"
      else
        raise ResolverError, "Only socks proxies supported"
      end
    end

    #
    # Find the nameservers to use for a given DNS request
    # @param _dns_message [Dnsruby::Message] The DNS message to be sent
    #
    # @return [Array<Array>] A list of nameservers, each with Rex::Socket options
    #
    def upstream_resolvers_for_packet(_dns_message)
      @config[:nameservers].map do |ns|
        UpstreamResolver.create_dns_server(ns.to_s)
      end
    end

    def upstream_resolvers_for_query(name, type = Dnsruby::Types::A, cls = Dnsruby::Classes::IN)
      name, type, cls = preprocess_query_arguments(name, type, cls)
      net_packet = make_query_packet(name, type, cls)
      # This returns a Net::DNS::Packet. Convert to Dnsruby::Message for consistency
      packet = Rex::Proto::DNS::Packet.encode_drb(net_packet)
      upstream_resolvers_for_packet(packet)
    end

    #
    # Send DNS request over appropriate transport and process response
    #
    # @param argument [Object] An object holding the DNS message to be processed.
    # @param type [Fixnum] Type of record to look up
    # @param cls [Fixnum] Class of question to look up
    # @return [Dnsruby::Message] DNS response
    #
    def send(argument, type = Dnsruby::Types::A, cls = Dnsruby::Classes::IN)
      case argument
      when Dnsruby::Message
        packet = argument
      when Net::DNS::Packet, Resolv::DNS::Message
        packet = Rex::Proto::DNS::Packet.encode_drb(argument)
      else
        net_packet = make_query_packet(argument,type,cls)
        # This returns a Net::DNS::Packet. Convert to Dnsruby::Message for consistency
        packet = Rex::Proto::DNS::Packet.encode_drb(net_packet)
      end


      upstream_resolvers = upstream_resolvers_for_packet(packet)
      if upstream_resolvers.empty?
        raise ResolverError, "No upstream resolvers specified!"
      end

      ans = nil
      upstream_resolvers.each do |upstream_resolver|
        case upstream_resolver.type
        when UpstreamResolver::Type::BLACK_HOLE
          ans = resolve_via_black_hole(upstream_resolver, packet, type, cls)
        when UpstreamResolver::Type::DNS_SERVER
          ans = resolve_via_dns_server(upstream_resolver, packet, type, cls)
        when UpstreamResolver::Type::STATIC
          ans = resolve_via_static(upstream_resolver, packet, type, cls)
        when UpstreamResolver::Type::SYSTEM
          ans = resolve_via_system(upstream_resolver, packet, type, cls)
        end

        break if (ans and ans[0].length > 0)
      end

      unless (ans and ans[0].length > 0)
        @logger.fatal "No response from upstream resolvers: aborting"
        raise NoResponseError
      end

      # response = Net::DNS::Packet.parse(ans[0],ans[1])
      response = Dnsruby::Message.decode(ans[0])

      if response.header.tc and not ignore_truncated?
        @logger.warn "Packet truncated, retrying using TCP"
        self.use_tcp = true
        begin
          return send(argument,type,cls)
        ensure
          self.use_tcp = false
        end
      end

      response
    end

    #
    # Send request over TCP
    #
    # @param packet [Net::DNS::Packet] Packet associated with packet_data
    # @param packet_data [String] Data segment of DNS request packet
    # @param nameservers [Array<[String,Hash]>] List of nameservers to use for this request, and their associated socket options
    # @param prox [String] Proxy configuration for TCP socket
    #
    # @return ans [String] Raw DNS reply
    def send_tcp(packet, packet_data, nameservers, prox = @config[:proxies])
      ans = nil
      length = [packet_data.size].pack("n")
      nameservers.each do |ns, socket_options|
        socket = nil
        config = {
          'PeerHost' => ns.to_s,
          'PeerPort' => @config[:port].to_i,
          'Proxies' => prox,
          'Context' => @config[:context],
          'Comm' => @config[:comm],
          'Timeout' => @config[:tcp_timeout]
        }
        config.update(socket_options)
        unless config['Comm'].nil? || config['Comm'].alive?
          @logger.warn("Session #{config['Comm'].sid} not active, and cannot be used to resolve DNS")
          next
        end

        suffix = " over session #{@config['Comm'].sid}" unless @config['Comm'].nil?
        if @config[:source_port] > 0
          config['LocalPort'] = @config[:source_port]
        end
        if @config[:source_host].to_s != '0.0.0.0'
          config['LocalHost'] = @config[:source_host] unless @config[:source_host].nil?
        end
        begin
          suffix = ''
          begin
            socket = Rex::Socket::Tcp.create(config)
          rescue
            @logger.warn "TCP Socket could not be established to #{ns}:#{@config[:port]} #{@config[:proxies]}#{suffix}"
            next
          end
          next unless socket #
          @logger.info "Contacting nameserver #{ns} port #{@config[:port]}#{suffix}"
          socket.write(length+packet_data)
          got_something = false
          loop do
            buffer = ""
            attempts = 3
            begin
              ans = socket.recv(2)
            rescue Errno::ECONNRESET
              @logger.warn "TCP Socket got Errno::ECONNRESET from #{ns}:#{@config[:port]} #{@config[:proxies]}#{suffix}"
              attempts -= 1
              retry if attempts > 0
            end
            if ans.size == 0
              if got_something
                break #Proper exit from loop
              else
                @logger.warn "Connection reset to nameserver #{ns}#{suffix}, trying next."
                throw :next_ns
              end
            end
            got_something = true
            len = ans.unpack("n")[0]

            @logger.info "Receiving #{len} bytes..."

            if len.nil? or len == 0
              @logger.warn "Receiving 0 length packet from nameserver #{ns}#{suffix}, trying next."
              throw :next_ns
            end

            while (buffer.size < len)
              left = len - buffer.size
              temp,from = socket.recvfrom(left)
              buffer += temp
            end

            unless buffer.size == len
              @logger.warn "Malformed packet from nameserver #{ns}#{suffix}, trying next."
              throw :next_ns
            end
            if block_given?
              yield [buffer,["",@config[:port],ns.to_s,ns.to_s]]
            else
              return [buffer,["",@config[:port],ns.to_s,ns.to_s]]
            end
          end
        rescue Timeout::Error
          @logger.warn "Nameserver #{ns}#{suffix} not responding within TCP timeout, trying next one"
          next
        ensure
          socket.close if socket
        end
      end
      return nil
    end

    #
    # Send request over UDP
    #
    # @param packet [Net::DNS::Packet] Packet associated with packet_data
    # @param packet_data [String] Data segment of DNS request packet
    # @param nameservers [Array<[String,Hash]>] List of nameservers to use for this request, and their associated socket options
    #
    # @return ans [String] Raw DNS reply
    def send_udp(packet,packet_data, nameservers)
      ans = nil
      nameservers.each do |ns, socket_options|
        begin
          config = {
            'PeerHost' => ns.to_s,
            'PeerPort' => @config[:port].to_i,
            'Context' => @config[:context],
            'Comm' => @config[:comm],
            'Timeout' => @config[:udp_timeout]
          }
          config.update(socket_options)
          unless config['Comm'].nil? || config['Comm'].alive?
            @logger.warn("Session #{config['Comm'].sid} not active, and cannot be used to resolve DNS")
            next
          end

          if @config[:source_port] > 0
            config['LocalPort'] = @config[:source_port]
          end
          if @config[:source_host] != IPAddr.new('0.0.0.0')
            config['LocalHost'] = @config[:source_host] unless @config[:source_host].nil?
          end
          socket = Rex::Socket::Udp.create(config)
        rescue
          @logger.warn "UDP Socket could not be established to #{ns}:#{@config[:port]}"
          next
        end
        @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
        #socket.sendto(packet_data, ns.to_s, @config[:port].to_i, 0)
        socket.write(packet_data)
        ans = socket.recvfrom(@config[:packet_size])
        break if ans
      rescue Timeout::Error
        @logger.warn "Nameserver #{ns} not responding within UDP timeout, trying next one"
        next
      end
      ans
    end


    #
    # Perform search using the configured searchlist and resolvers
    #
    # @param name
    # @param type [Fixnum] Type of record to look up
    # @param cls [Fixnum] Class of question to look up
    #
    # @return ans [Dnsruby::Message] DNS Response
    def search(name, type = Dnsruby::Types::A, cls = Dnsruby::Classes::IN)
      return query(name,type,cls) if name.class == IPAddr
      # If the name contains at least one dot then try it as is first.
      if name.include? "."
        @logger.debug "Search(#{name},#{Dnsruby::Types.new(type)},#{Dnsruby::Classes.new(cls)})"
        ans = query(name,type,cls)
        return ans if ans.header.ancount > 0
      end
      # If the name doesn't end in a dot then apply the search list.
      if name !~ /\.$/ and @config[:dns_search]
        @config[:searchlist].each do |domain|
          newname = name + "." + domain
          @logger.debug "Search(#{newname},#{Dnsruby::Types.new(type)},#{Dnsruby::Classes.new(cls)})"
          ans = query(newname,type,cls)
          return ans if ans.header.ancount > 0
        end
      end
      # Finally, if the name has no dots then try it as is.
      @logger.debug "Search(#{name},#{Dnsruby::Types.new(type)},#{Dnsruby::Classes.new(cls)})"
      return query(name+".",type,cls)
    end

    #
    # Perform query with default domain validation
    #
    # @param name
    # @param type [Fixnum] Type of record to look up
    # @param cls [Fixnum] Class of question to look up
    #
    # @return ans [Dnsruby::Message] DNS Response
    def query(name, type = Dnsruby::Types::A, cls = Dnsruby::Classes::IN)
      name, type, cls = preprocess_query_arguments(name, type, cls)
      @logger.debug "Query(#{name},#{Dnsruby::Types.new(type)},#{Dnsruby::Classes.new(cls)})"
      send(name,type,cls)
    end

    def self.default_config_file
      %w[
        /etc/resolv.conf
        /data/data/com.termux/files/usr/etc/resolv.conf
      ].find do |path|
        File.file?(path) && File.readable?(path)
      end
    end

    private

    def preprocess_query_arguments(name, type, cls)
      return [name, type, cls] if name.class == IPAddr

      # If the name doesn't contain any dots then append the default domain.
      if name !~ /\./ and name !~ /:/ and @config[:defname]
        name += "." + @config[:domain]
      end
      [name, type, cls]
    end

    def resolve_via_dns_server(upstream_resolver, packet, type, _cls)
      method = self.use_tcp? ? :send_tcp : :send_udp

      # Store packet_data for performance improvements,
      # so methods don't keep on calling Packet#encode
      packet_data = packet.encode
      packet_size = packet_data.size

      # Choose whether use TCP, UDP
      if packet_size > @config[:packet_size] # Must use TCP
        @logger.info "Sending #{packet_size} bytes using TCP due to size"
        method = :send_tcp
      else # Packet size is inside the boundaries
        if use_tcp? or !(proxies.nil? or proxies.empty?) # User requested TCP
          @logger.info "Sending #{packet_size} bytes using TCP due to tcp flag"
          method = :send_tcp
        elsif !supports_udp?(upstream_resolver)
          @logger.info "Sending #{packet_size} bytes using TCP due to the presence of a non-UDP-compatible comm channel"
          method = :send_tcp
        else # Finally use UDP
          @logger.info "Sending #{packet_size} bytes using UDP"
          method = :send_udp unless method == :send_tcp
        end
      end

      if type == Dnsruby::Types::AXFR
        @logger.warn "AXFR query, switching to TCP" unless method == :send_tcp
        method = :send_tcp
      end

      nameserver = [upstream_resolver.destination, upstream_resolver.socket_options]
      ans = self.__send__(method, packet, packet_data, [nameserver])

      if (ans and ans[0].length > 0)
        @logger.info "Received #{ans[0].size} bytes from #{ans[1][2]+":"+ans[1][1].to_s}"
      end

      ans
    end

    def resolve_via_black_hole(upstream_resolver, packet, type, cls)
      # do not just return nil because that will cause the next resolver to be used
      @logger.info "No response from upstream resolvers: black-hole"
      raise NoResponseError
    end

   def resolve_via_static(upstream_resolver, packet, type, cls)
      simple_name_lookup(upstream_resolver, packet, type, cls) do |name, _family|
        static_hostnames.get(name, type)
      end
   end

    def resolve_via_system(upstream_resolver, packet, type, cls)
      # This system resolver will use host operating systems `getaddrinfo` (or equivalent function) to perform name
      # resolution. This is primarily useful if that functionality is hooked or modified by an external application such
      # as proxychains. This handler though can only process A and AAAA requests.
      simple_name_lookup(upstream_resolver, packet, type, cls) do |name, family|
        addrinfos = ::Addrinfo.getaddrinfo(name, 0, family, ::Socket::SOCK_STREAM)
        addrinfos.map(&:ip_address)
      end
    end

    def simple_name_lookup(upstream_resolver, packet, type, cls, &block)
      return nil unless cls == Dnsruby::Classes::IN

      # todo: make sure this will work if the packet has multiple questions, figure out how that's handled
      name = packet.question.first.qname.to_s
      case type
      when Dnsruby::Types::A
        family = ::Socket::AF_INET
      when Dnsruby::Types::AAAA
        family = ::Socket::AF_INET6
      else
        return nil
      end

      ip_addresses = nil
      begin
        ip_addresses = block.call(name, family)
      rescue StandardError => e
        @logger.error("The #{upstream_resolver.type} name lookup block failed for #{name}")
      end
      return nil unless ip_addresses && !ip_addresses.empty?

      message = Dnsruby::Message.new
      message.add_question(name, type, cls)
      ip_addresses.each do |ip_address|
        message.add_answer(Dnsruby::RR.new_from_hash(
          name: name,
          type: type,
          ttl: 0,
          address: ip_address.to_s
        ))
      end
      [message.encode]
    end

    def supports_udp?(upstream_resolver)
      return false unless upstream_resolver.type == UpstreamResolver::Type::DNS_SERVER

      comm = upstream_resolver.socket_options.fetch('Comm') { @config[:comm] || Rex::Socket::SwitchBoard.best_comm(upstream_resolver.destination) }
      return false if comm && !comm.supports_udp?

      true
    end
  end # Resolver

end
end
end
