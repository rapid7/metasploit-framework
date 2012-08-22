require 'rex'

##
# Provides Rex::Sockets compatible methods for Net::DNS::Resolver
##

module Net # :nodoc:
  module DNS
    class Resolver

      def proxies
        @config[:proxies].inspect
      end

      def proxies=(arg)
        if arg.is_a?(String) and arg.strip =~ /^socks/i
          @config[:proxies] = arg.strip
          @config[:use_tcp] = true
          self.tcp_timeout = self.tcp_timeout.to_s.to_i + 250
          @logger.info "SOCKS proxy set, using TCP, increasing timeout"
        else
          raise ResolverError, "Only socks proxies supported"
        end
      end

      def send(argument,type=Net::DNS::A,cls=Net::DNS::IN)
        if @config[:nameservers].size == 0
          raise ResolverError, "No nameservers specified!"
        end

        method = self.use_tcp? ? :send_tcp : :send_udp

        if argument.kind_of? Net::DNS::Packet
          packet = argument
        else
          packet = make_query_packet(argument,type,cls)
        end

        # Store packet_data for performance improvements,
        # so methods don't keep on calling Packet#data
        packet_data = packet.data
        packet_size = packet_data.size

        # Choose whether use TCP, UDP
        if packet_size > @config[:packet_size] # Must use TCP
          @logger.info "Sending #{packet_size} bytes using TCP"
          method = :send_tcp
        else # Packet size is inside the boundaries
          if use_tcp? or !(proxies.nil? or proxies.empty?) # User requested TCP
            @logger.info "Sending #{packet_size} bytes using TCP"
            method = :send_tcp
          else # Finally use UDP
            @logger.info "Sending #{packet_size} bytes using UDP"
            method = :send_udp unless method == :send_tcp 
          end
        end

        if type == Net::DNS::AXFR
          @logger.warn "AXFR query, switching to TCP" unless method == :send_tcp
          method = :send_tcp
        end

        ans = eval "self.#{method.to_s}(packet,packet_data)"

        unless (ans and ans[0].length > 0)
          @logger.fatal "No response from nameservers list: aborting"
          raise NoResponseError
          return nil
        end

        @logger.info "Received #{ans[0].size} bytes from #{ans[1][2]+":"+ans[1][1].to_s}"
        response = Net::DNS::Packet.parse(ans[0],ans[1])

        if response.header.truncated? and not ignore_truncated?
          @logger.warn "Packet truncated, retrying using TCP"
          self.use_tcp = true
          begin
            return send(argument,type,cls)
          ensure
            self.use_tcp = false
          end
        end

        return response
      end

      # TODO: figure out how to pass proxies from datastore
      def send_tcp(packet,packet_data)
        ans = nil
        length = [packet_data.size].pack("n")
        @config[:nameservers].each do |ns|
          begin
            buffer = ""
            @config[:tcp_timeout].timeout do
              begin
                begin
                  socket = Rex::Socket::Tcp.create(
                    'PeerHost' => ns.to_s,
                    'PeerPort' => @config[:port].to_i,
                    'Proxies' => @config[:proxies]
                  )
                rescue
                  @logger.warn "TCP Socket could not be established to #{ns}:#{@config[:port]} #{@config[:proxies]}"
                  return nil
                end
                next unless socket #
                @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
                socket.write(length+packet_data)
                ans = socket.recv(Net::DNS::INT16SZ)
                len = ans.unpack("n")[0]

                @logger.info "Receiving #{len} bytes..."

                if len == 0
                  @logger.warn "Receiving 0 length packet from nameserver #{ns}, trying next."
                  next
                end

                while (buffer.size < len)
                  left = len - buffer.size
                  temp,from = socket.recvfrom(left)
                  buffer += temp
                end

                unless buffer.size == len
                  @logger.warn "Malformed packet from nameserver #{ns}, trying next."
                  next
                end
              ensure
                socket.close if socket
              end
            end
            return [buffer,["",@config[:port],ns.to_s,ns.to_s]]
          rescue Timeout::Error
            @logger.warn "Nameserver #{ns} not responding within TCP timeout, trying next one"
            next
          end
        end
      end

      def send_udp(packet,packet_data)
        ans = nil
        response = ""
        @config[:nameservers].each do |ns|
          begin
            @config[:udp_timeout].timeout do
              begin
                socket = Rex::Socket::Udp.create(
                  'PeerHost' => ns.to_s,
                  'PeerPort' => @config[:port].to_i
                )
              rescue
                @logger.warn "UDP Socket could not be established to #{ns}:#{@config[:port]}"
                return nil
              end
              @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
              #socket.sendto(packet_data, ns.to_s, @config[:port].to_i, 0)
              socket.write(packet_data)
              ans = socket.recvfrom(@config[:packet_size])
            end
            break if ans
          rescue Timeout::Error
            @logger.warn "Nameserver #{ns} not responding within UDP timeout, trying next one"
            next
          end
        end
        ans
      end

    end # class Resolver
  end # module DNS
end # module Net