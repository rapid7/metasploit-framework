module EventMachine
  module DNS
    class Resolver

      def self.windows?
        if RUBY_PLATFORM =~ /mswin32|cygwin|mingw|bccwin/
          require 'win32/resolv'
          true
        else
          false
        end
      end

      HOSTS_FILE = windows? ? Win32::Resolv.get_hosts_path : '/etc/hosts'

      @hosts = nil
      @nameservers = nil
      @socket = nil

      def self.resolve(hostname)
        Request.new(socket, hostname)
      end

      def self.socket
        if @socket && @socket.error?
          @socket = Socket.open
        else
          @socket ||= Socket.open
        end
      end

      def self.nameservers=(ns)
        @nameservers = ns
      end

      def self.nameservers
        return @nameservers if @nameservers

        if windows?
          _, ns = Win32::Resolv.get_resolv_info
          return @nameservers = ns || []
        end

        @nameservers = []
        IO.readlines('/etc/resolv.conf').each do |line|
          if line =~ /^nameserver (.+)$/
            @nameservers << $1.split(/\s+/).first
          end
        end

        @nameservers
      rescue
        @nameservers = []
      end

      def self.nameserver
        nameservers.shuffle.first
      end

      def self.hosts
        return @hosts if @hosts

        @hosts = {}
        IO.readlines(HOSTS_FILE).each do |line|
          next if line =~ /^#/
          addr, host = line.split(/\s+/)

          next unless addr && host
          @hosts[host] ||= []
          @hosts[host] << addr
        end

        @hosts
      rescue
        @hosts = {}
      end
    end

    class RequestIdAlreadyUsed < RuntimeError; end

    class Socket < EventMachine::Connection
      def self.open
        EventMachine::open_datagram_socket('0.0.0.0', 0, self)
      end

      def initialize
        @nameserver = nil
      end

      def post_init
        @requests = {}
      end

      def start_timer
        @timer ||= EM.add_periodic_timer(0.1, &method(:tick))
      end

      def stop_timer
        EM.cancel_timer(@timer)
        @timer = nil
      end

      def unbind
      end

      def tick
        @requests.each do |id,req|
          req.tick
        end
      end

      def register_request(id, req)
        if @requests.has_key?(id)
          raise RequestIdAlreadyUsed
        else
          @requests[id] = req
        end

        start_timer
      end

      def deregister_request(id, req)
        @requests.delete(id)
        stop_timer if @requests.length == 0
      end

      def send_packet(pkt)
        send_datagram(pkt, nameserver, 53)
      end

      def nameserver=(ns)
        @nameserver = ns
      end

      def nameserver
        @nameserver || Resolver.nameserver
      end

      # Decodes the packet, looks for the request and passes the
      # response over to the requester
      def receive_data(data)
        msg = nil
        begin
          msg = Resolv::DNS::Message.decode data
        rescue
        else
          req = @requests[msg.id]
          if req
            @requests.delete(msg.id)
            stop_timer if @requests.length == 0
            req.receive_answer(msg)
          end
        end
      end
    end

    class Request
      include Deferrable
      attr_accessor :retry_interval, :max_tries

      def initialize(socket, hostname)
        @socket = socket
        @hostname = hostname
        @tries = 0
        @last_send = Time.at(0)
        @retry_interval = 3
        @max_tries = 5

        if addrs = Resolver.hosts[hostname]
          succeed addrs
        else
          EM.next_tick { tick }
        end
      end

      def tick
        # Break early if nothing to do
        return if @last_send + @retry_interval > Time.now
        if @tries < @max_tries
          send
        else
          @socket.deregister_request(@id, self)
          fail 'retries exceeded'
        end
      end

      def receive_answer(msg)
        addrs = []
        msg.each_answer do |name,ttl,data|
          if data.kind_of?(Resolv::DNS::Resource::IN::A) ||
              data.kind_of?(Resolv::DNS::Resource::IN::AAAA)
            addrs << data.address.to_s
          end
        end

        if addrs.empty?
          fail "rcode=#{msg.rcode}"
        else
          succeed addrs
        end
      end

      private

        def send
          @tries += 1
          @last_send = Time.now
          @socket.send_packet(packet.encode)
        end

        def id
          begin
            @id = rand(65535)
            @socket.register_request(@id, self)
          rescue RequestIdAlreadyUsed
            retry
          end unless defined?(@id)

          @id
        end

        def packet
          msg = Resolv::DNS::Message.new
          msg.id = id
          msg.rd = 1
          msg.add_question @hostname, Resolv::DNS::Resource::IN::A
          msg
        end

    end
  end
end
