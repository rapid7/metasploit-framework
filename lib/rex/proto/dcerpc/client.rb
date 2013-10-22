# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
class Client

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/proto/dcerpc/exceptions'
require 'rex/text'
require 'rex/proto/smb/exceptions'

  attr_accessor :handle, :socket, :options, :last_response, :context, :no_bind, :ispipe, :smb

  # initialize a DCE/RPC Function Call
  def initialize(handle, socket, useroptions = Hash.new)
    self.handle = handle
    self.socket = socket
    self.options = {
      'smb_user'   => '',
      'smb_pass'   => '',
      'smb_pipeio' => 'rw',
      'smb_name'   => nil,
      'read_timeout'    => 10,
      'connect_timeout' => 5
    }

    self.options.merge!(useroptions)

    # If the caller passed us a smb_client object, use it and
    # and skip the connect/login/ipc$ stages of the setup
    if (self.options['smb_client'])
      self.smb = self.options['smb_client']
    end

    # we must have a valid handle, regardless of everything else
    raise ArgumentError, 'handle is not a Rex::Proto::DCERPC::Handle' if !self.handle.is_a?(Rex::Proto::DCERPC::Handle)

    # we do this in case socket needs setup first, ie, socket = nil
    if !self.options['no_socketsetup']
      self.socket_check()
    end

    raise ArgumentError, 'socket can not read' if !self.socket.respond_to?(:read)
    raise ArgumentError, 'socket can not write' if !self.socket.respond_to?(:write)

    if !self.options['no_autobind']
      self.bind()
    end
  end

  def socket_check()
    if self.socket == nil
      self.socket_setup()
    end

    case self.handle.protocol
      when 'ncacn_ip_tcp'
        if self.socket.type? != 'tcp'
          raise "ack, #{self.handle.protocol} requires socket type tcp, not #{self.socket.type?}!"
        end
      when 'ncacn_np'
        if self.socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe
          self.ispipe = 1
        elsif self.socket.type? == 'tcp'
          self.smb_connect()
        else
          raise "ack, #{self.handle.protocol} requires socket type tcp, not #{self.socket.type?}!"
        end
        # No support ncacn_ip_udp (is it needed now that its ripped from Vista?)
      else
        raise "Unsupported protocol : #{self.handle.protocol}"
    end
  end

  # Create the appropriate socket based on protocol
  def socket_setup()
    ctx = { 'Msf' => self.options['Msf'], 'MsfExploit' => self.options['MsfExploit'] }
    self.socket = case self.handle.protocol

      when 'ncacn_ip_tcp'
        Rex::Socket.create_tcp(
          'PeerHost' => self.handle.address,
          'PeerPort' => self.handle.options[0],
          'Context' => ctx,
          'Timeout' => self.options['connect_timeout']
        )

      when 'ncacn_np'
        begin
          socket = Rex::Socket.create_tcp(
            'PeerHost' => self.handle.address,
            'PeerPort' => 445,
            'Context' => ctx,
            'Timeout' => self.options['connect_timeout']
          )
        rescue ::Timeout::Error, Rex::ConnectionRefused
          socket = Rex::Socket.create_tcp(
            'PeerHost' => self.handle.address,
            'PeerPort' => 139,
            'Context' => ctx,
            'Timeout' => self.options['connect_timeout']
          )
        end
        socket
      else nil
    end

    # Add this socket to the exploit's list of open sockets
    options['MsfExploit'].add_socket(self.socket) if (options['MsfExploit'])
  end

  def smb_connect()
    require 'rex/proto/smb/simpleclient'

    if(not self.smb)
      if self.socket.peerport == 139
        smb = Rex::Proto::SMB::SimpleClient.new(self.socket)
      else
        smb = Rex::Proto::SMB::SimpleClient.new(self.socket, true)
      end

      smb.login('*SMBSERVER', self.options['smb_user'], self.options['smb_pass'])
      smb.connect("\\\\#{self.handle.address}\\IPC$")
      self.smb = smb
      self.smb.read_timeout = self.options['read_timeout']
    end

    f = self.smb.create_pipe(self.handle.options[0])
    f.mode = self.options['smb_pipeio']
    self.socket = f
  end

  def read()

    max_read = self.options['pipe_read_max_size'] || 1024*1024
    min_read = self.options['pipe_read_min_size'] || max_read

    raw_response = ''

    # Are we reading from a remote pipe over SMB?
    if (self.socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe)
      begin

        # Max SMB read is 65535, cap it at 64000
        max_read = [64000, max_read].min
        min_read = [64000, min_read].min

        read_limit = nil

        while(true)
          # Random read offsets will not work on Windows NT 4.0 (thanks Dave!)

          read_cnt = (rand(max_read-min_read)+min_read)
          if(read_limit)
            if(read_cnt + raw_response.length > read_limit)
              read_cnt = raw_response.length - read_limit
            end
          end

          data = self.socket.read( read_cnt, rand(1024)+1)
          break if !(data and data.length > 0)
          raw_response += data

          # Keep reading until we have at least the DCERPC header
          next if raw_response.length < 10

          # We now have to process the raw_response and parse out the DCERPC fragment length
          # if we have read enough data. Once we have the length value, we need to make sure
          # that we don't read beyond this amount, or it can screw up the SMB state
          if (not read_limit)
            begin
              check = Rex::Proto::DCERPC::Response.new(raw_response)
              read_limit = check.frag_len
            rescue ::Rex::Proto::DCERPC::Exceptions::InvalidPacket
            end
          end
          break if (read_limit and read_limit <= raw_response.length)
        end

      rescue Rex::Proto::SMB::Exceptions::NoReply
        # I don't care if I didn't get a reply...
      rescue Rex::Proto::SMB::Exceptions::ErrorCode => exception
        if exception.error_code != 0xC000014B
          raise exception
        end
      end
    # This must be a regular TCP or UDP socket
    else
      if (self.socket.type? == 'tcp')
        if (false and max_read)
          while (true)
            data = self.socket.get_once((rand(max_read-min_read)+min_read), self.options['read_timeout'])
            break if not data
            break if not data.length
            raw_response << data
          end
        else
          # Just read the entire response in one go
          raw_response = self.socket.get_once(-1, self.options['read_timeout'])
        end
      else
        # No segmented read support for non-TCP sockets
        raw_response = self.socket.read(0xFFFFFFFF / 2 - 1)  # read max data
      end
    end

    raw_response
  end

  # Write data to the underlying socket, limiting the sizes of the writes based on
  # the pipe_write_min / pipe_write_max options.
  def write(data)

    max_write = self.options['pipe_write_max_size'] || data.length
    min_write = self.options['pipe_write_min_size'] || max_write

    if(min_write > max_write)
      max_write = min_write
    end

    idx = 0

    if (self.socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe)
      while(idx < data.length)
        bsize = (rand(max_write-min_write)+min_write).to_i
        len = self.socket.write(data[idx, bsize], rand(1024)+1)
        idx += bsize
      end
    else
      self.socket.write(data)
    end

    data.length
  end

  def bind()
    require 'rex/proto/dcerpc/packet'
    bind = ''
    context = ''
    if self.options['fake_multi_bind']

      args = [ self.handle.uuid[0], self.handle.uuid[1] ]

      if (self.options['fake_multi_bind_prepend'])
        args << self.options['fake_multi_bind_prepend']
      end

      if (self.options['fake_multi_bind_append'])
        args << self.options['fake_multi_bind_append']
      end

      bind, context = Rex::Proto::DCERPC::Packet.make_bind_fake_multi(*args)
    else
      bind, context = Rex::Proto::DCERPC::Packet.make_bind(*self.handle.uuid)
    end

    raise 'make_bind failed' if !bind

    self.write(bind)
    raw_response = self.read()

    response = Rex::Proto::DCERPC::Response.new(raw_response)
    self.last_response = response
    if response.type == 12 or response.type == 15
      if self.last_response.ack_result[context] == 2
        raise "Could not bind to #{self.handle}"
      end
      self.context = context
    else
      raise "Could not bind to #{self.handle}"
    end
  end

  # Perform a DCE/RPC Function Call
  def call(function, data, do_recv = true)

    frag_size = data.length
    if options['frag_size']
      frag_size = options['frag_size']
    end
    object_id = ''
    if options['object_call']
      object_id = self.handle.uuid[0]
    end
    if options['random_object_id']
      object_id = Rex::Proto::DCERPC::UUID.uuid_unpack(Rex::Text.rand_text(16))
    end

    call_packets = Rex::Proto::DCERPC::Packet.make_request(function, data, frag_size, self.context, object_id)
    call_packets.each { |packet|
      self.write(packet)
    }

    return true if not do_recv

    raw_response = ''

    begin
      raw_response = self.read()
    rescue ::EOFError
      raise Rex::Proto::DCERPC::Exceptions::NoResponse
    end

    if (raw_response == nil or raw_response.length == 0)
      raise Rex::Proto::DCERPC::Exceptions::NoResponse
    end


    self.last_response = Rex::Proto::DCERPC::Response.new(raw_response)

    if self.last_response.type == 3
      e = Rex::Proto::DCERPC::Exceptions::Fault.new
      e.fault = self.last_response.status
      raise e
    end

    self.last_response.stub_data
  end

  # Process a DCERPC response packet from a socket
  def self.read_response(socket, timeout=self.options['read_timeout'])

    data = socket.get_once(-1, timeout)

    # We need at least 10 bytes to find the FragLen
    if (! data or data.length() < 10)
      return
    end

    # Pass the first 10 bytes to the constructor
    resp = Rex::Proto::DCERPC::Response.new(data.slice!(0, 10))

    # Something went wrong in the parser...
    if (! resp.frag_len)
      return resp
    end

    # Do we need to read more data?
    if (resp.frag_len > (data.length + 10))
      begin
        data << socket.timed_read(resp.frag_len - data.length - 10, timeout)
      rescue Timeout::Error
      end
    end

    # Still missing some data...
    if (data.length() != resp.frag_len - 10)
      # TODO: Bubble this up somehow
      # $stderr.puts "Truncated DCERPC response :-("
      return resp
    end

    resp.parse(data)
    return resp
  end

end
end
end
end

