# -*- coding: binary -*-

require 'net/dns/resolver'

module Rex
module Proto
module DNS

  ##
  # Provides Rex::Sockets compatible version of Net::DNS::Resolver
  # Modified to work with Dnsruby::Messages, their resolvers are too heavy
  ##
  class CachedResolver < Resolver
    include Rex::Proto::DNS::Constants
    attr_accessor :cache

    #
    # Initialize resolver with cache
    #
    # @param config [Hash] Resolver config
    #
    # @return [nil]
    def initialize(config = {})
      super(config)
      self.cache = Rex::Proto::DNS::Cache.new
      # Read hostsfile into cache
      hf = Rex::Compat.is_windows ? '%WINDIR%/system32/drivers/etc/hosts' : '/etc/hosts'
      entries = begin
        File.read(hf).lines.map(&:strip).select do |entry|
          Rex::Socket.is_ip_addr?(entry.gsub(/\s+/,' ').split(' ').first) and
          not entry.match(/::.*ip6-/) # Ignore Debian/Ubuntu-specific notation for IPv6 hosts
        end.map do |entry|
          entry.gsub(/\s+/,' ').split(' ')
        end
      rescue => e
        @logger.error(e)
        []
      end
      entries.each do |ent|
        next if ent.first =~ /^127\./
        # Deal with multiple hostnames per address
        while ent.length > 2
          hostname = ent.pop
          next unless MATCH_HOSTNAME.match hostname
          begin
            if Rex::Socket.is_ipv4?(ent.first)
              self.cache.add_static(hostname, ent.first, Dnsruby::Types::A)
            elsif Rex::Socket.is_ipv6?(ent.first)
              self.cache.add_static(hostname, ent.first, Dnsruby::Types::AAAA)
            else
              raise "Unknown IP address format #{ent.first} in hosts file!"
            end
          rescue => e
            # Deal with edge-cases in users' hostsfile
            @logger.error(e)
          end
        end
        hostname = ent.pop
        begin
          if MATCH_HOSTNAME.match hostname
            if Rex::Socket.is_ipv4?(ent.first)
              self.cache.add_static(hostname, ent.first, Dnsruby::Types::A)
            elsif Rex::Socket.is_ipv6?(ent.first)
              self.cache.add_static(hostname, ent.first, Dnsruby::Types::AAAA)
            else
              raise "Unknown IP address format #{ent.first} in hosts file!"
            end
          end
        rescue => e
          # Deal with edge-cases in users' hostsfile
          @logger.error(e)
        end
      end
      # TODO: inotify or similar on hostsfile for live updates? Easy-button functionality
      self.cache.start unless config[:dns_cache_no_start]
      return
    end

    #
    # Attempt to find answers to query in DNS cache; failing that,
    # send remainder of DNS queries over appropriate transport and
    # cache answers before returning to caller.
    #
    # @param argument [Object] An object holding the DNS message to be processed.
    # @param type [Fixnum] Type of record to look up
    # @param cls [Fixnum] Class of question to look up
    #
    # @return [Dnsruby::Message, nil] DNS response on success, nil on failure.
    def send(argument, type = Dnsruby::Types::A, cls = Dnsruby::Classes::IN)
      case argument
      when Dnsruby::Message
        req = argument
      when Net::DNS::Packet, Resolv::DNS::Message
        req = Rex::Proto::DNS::Packet.encode_drb(argument)
      else
        net_packet = make_query_packet(argument,type,cls)
        # This returns a Net::DNS::Packet. Convert to Dnsruby::Message for consistency
        req = Rex::Proto::DNS::Packet.encode_drb(net_packet)
      end
      resolve = req.dup
      # Find cached items, remove request from resolved packet
      req.question.each do |ques|
        cached = self.cache.find(ques.qname, ques.qtype.to_s)
        next if cached.empty?
        req.instance_variable_set(:@answer, (req.answer + cached).uniq)
        resolve.question.delete(ques)
      end
      # Resolve remaining requests, cache responses
      if resolve.question.count > 0
        resolved = super(resolve, type)
        req.instance_variable_set(:@answer, (req.answer + resolved.answer).uniq)
        resolved.answer.each do |ans|
          self.cache.cache_record(ans)
        end
      end
      # Finalize answers in response
      # Check for empty response prior to sending
      req.header.rcode = Dnsruby::RCode::NOERROR if req.answer.size < 1
      req.header.qr = true # Set response bit
      return req
    end
  end
end
end
end
