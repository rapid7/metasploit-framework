# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::MsTds
  class Channel
    include Rex::IO::StreamAbstraction

    attr_reader :params

    # the socket that makes the outbound connection to the SQL server
    attr_reader :sock

    def initialize(opts = {})
      @params = Rex::Socket::Parameters.from_hash(opts)

      # it doesn't work this way so throw an exception so that's clear
      raise RuntimeError.new('SSL incompatible with MsTds::Socket') if @params.ssl
      raise ArgumentError.new('MsTds::Socket must be TCP') if @params.proto != 'tcp'

      @sock = Rex::Socket.create_param(@params)
      initialize_abstraction

      lsock.initinfo(@sock.peerinfo, @sock.localinfo)

      monitor_sock(@sock, sink: method(:_read_handler), name: 'MonitorLocal', on_exit: method(:_exit_handler))
    end

    def write(buf, opts = {})
      if negotiating_ssl?
        Rex::IO::RelayManager.io_write_all(self.sock, [18, 0x01, buf.length + 8, 0x0000, 0x00, 0x00].pack('CCnnCC') + buf) - 8
      else
        Rex::IO::RelayManager.io_write_all(self.sock, buf)
      end
    end

    def starttls
      self.lsock.starttls(params)
    end

    protected

    def negotiating_ssl?
      return false unless self.lsock.is_a?(Rex::Socket::SslTcp)
      return false if self.lsock.sslsock.state.start_with?('SSLOK')

      true
    end

    def _exit_handler
      self.rsock.close
    end

    def _read_handler(buf)
      if negotiating_ssl?
        Rex::IO::RelayManager.io_write_all(self.rsock, buf[8..]) + 8
      else
        Rex::IO::RelayManager.io_write_all(self.rsock, buf)
      end
    end
  end
end
