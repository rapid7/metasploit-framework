# -*- coding: binary -*-
require 'thread'
require 'rex/socket'

module Rex
module Services

###
#
# This service acts as a local TCP relay whereby clients can connect to a
# local listener that forwards to an arbitrary remote endpoint.  Interaction
# with the remote endpoint socket requires that it implement the
# Rex::IO::Stream interface.
#
###
class LocalRelay

  include Rex::Service

  ###
  #
  # This module is used to extend streams such that they can be associated
  # with a relay context and the other side of the stream.
  #
  ###
  module Stream

    #
    # This method is called when the other side has data that has been read
    # in.
    #
    def on_other_data(data)
      if relay.on_other_data_proc
        relay.on_other_data_proc.call(relay, self, data)
      else
        put(data)
      end
    end

    attr_accessor :relay
    attr_accessor :other_stream
  end

  ###
  #
  # This module is used to extend stream servers such that they can be
  # associated with a relay context.
  #
  ###
  module StreamServer

    #
    # This method is called when the stream server receives a local
    # connection such that the remote half can be allocated.  The return
    # value of the callback should be a Stream instance.
    #
    def on_local_connection(relay, lfd)
      if relay.on_local_connection_proc
        relay.on_local_connection_proc.call(relay, lfd)
      end
    end

    attr_accessor :relay
  end

  ###
  #
  # This class acts as an instance of a given local relay.
  #
  ###
  class Relay

    def initialize(name, listener, opts = {})
      self.name                     = name
      self.listener                 = listener
      self.opts                     = opts
      self.on_local_connection_proc = opts['OnLocalConnection']
      self.on_conn_close_proc       = opts['OnConnectionClose']
      self.on_other_data_proc       = opts['OnOtherData']
      if (not $dispatcher['rex'])
        register_log_source('rex', $dispatcher['core'], get_log_level('core'))
      end
    end

    def shutdown
      begin
        listener.shutdown if listener
      rescue ::Exception
      end
    end

    def close
      begin
        listener.close if listener
      rescue ::Exception
      end
      listener = nil
    end

    attr_reader :name, :listener, :opts
    attr_accessor :on_local_connection_proc
    attr_accessor :on_conn_close_proc
    attr_accessor :on_other_data_proc
  protected
    attr_writer :name, :listener, :opts

  end

  ###
  #
  # This class acts as an instance of a local relay handling a reverse connection
  #
  ###
  class ReverseRelay < Relay

    def initialize(name, channel, opts = {})

      self.name                     = name
      self.listener                 = nil
      self.opts                     = opts
      self.on_local_connection_proc = opts['OnLocalConnection']
      self.on_conn_close_proc       = opts['OnConnectionClose']
      self.on_other_data_proc       = opts['OnOtherData']
      self.channel                  = channel

      if !$dispatcher['rex']
        register_log_source('rex', $dispatcher['core'], get_log_level('core'))
      end
    end

    def shudown
      # don't need to do anything here, it's only "close" we care about
    end

    def close
      self.channel.close if self.channel
      self.channel = nil
    end

    attr_reader :channel

    protected
      attr_writer :channel

  end

  #
  # Initializes the local tcp relay monitor.
  #
  def initialize
    self.relays       = Hash.new
    self.rfds         = Array.new
    self.rev_chans    = Array.new
    self.relay_thread = nil
    self.relay_mutex  = Mutex.new
  end

  ##
  #
  # Service interface implementors
  #
  ##

  #
  # Returns the hardcore alias for the local relay service.
  #
  def self.hardcore_alias(*args)
    "__#{args}"
  end

  #
  # Returns the alias for this service.
  #
  def alias
    super || "Local Relay"
  end

  #
  # Starts the thread that monitors the local relays.
  #
  def start
    if (!self.relay_thread)
      self.relay_thread = Rex::ThreadFactory.spawn("LocalRelay", false) {
        begin
          monitor_relays
        rescue ::Exception
          elog("Error in #{self} monitor_relays: #{$!}", 'rex')
        end
      }
    end
  end

  #
  # Stops the thread that monitors the local relays and destroys all
  # listeners, both local and remote.
  #
  def stop
    if (self.relay_thread)
      self.relay_thread.kill
      self.relay_thread = nil
    end

    self.relay_mutex.synchronize {
      self.relays.delete_if { |k, v|
        v.shutdown
        v.close
        true
      }
    }

    # make sure we kill off active sockets when we shut down
    while self.rfds.length > 0
      close_relay_conn(self.rfds.shift) rescue nil
    end

    # we can safely clear the channels array because all of the
    # reverse relays were closed down
    self.rev_chans.clear
    self.relays.clear
  end

  #
  # Start a new active listener on the victim ready for reverse connections.
  #
  def start_reverse_tcp_relay(channel, opts = {})
    opts['__RelayType'] = 'tcp'
    opts['Reverse'] = true

    name = "Reverse-#{opts['LocalPort']}"

    relay = ReverseRelay.new(name, channel, opts)

    # dirty hack to get "relay" support?
    channel.extend(StreamServer)
    channel.relay = relay

    self.relay_mutex.synchronize {
      self.relays[name] = relay
      self.rev_chans << channel
    }
  end

  #
  # Stop an active reverse port forward.
  #
  def stop_reverse_tcp_relay(rport)
    stop_relay("Reverse-#{rport}")
  end

  #
  # Starts a local TCP relay.
  #
  def start_tcp_relay(lport, opts = {})
    # Make sure our options are valid
    if ((opts['PeerHost'] == nil or opts['PeerPort'] == nil) and (opts['Stream'] != true))
      raise ArgumentError, "Missing peer host or peer port.", caller
    end

    listener = Rex::Socket.create_tcp_server(
      'LocalHost' => opts['LocalHost'],
      'LocalPort' => lport)

    opts['LocalPort']   = lport
    opts['__RelayType'] = 'tcp'

    start_relay(listener, lport.to_s + (opts['LocalHost'] || '0.0.0.0'), opts)
  end

  #
  # Starts a local relay on the supplied local port.  This listener will call
  # the supplied callback procedures when various events occur.
  #
  def start_relay(stream_server, name, opts = {})
    # Create a Relay instance with the local stream and remote stream
    relay = Relay.new(name, stream_server, opts)

    # Extend the stream_server so that we can associate it with this relay
    stream_server.extend(StreamServer)
    stream_server.relay = relay

    # Add the stream associations the appropriate lists and hashes
    self.relay_mutex.synchronize {
      self.relays[name] = relay

      self.rfds << stream_server
    }
  end

  #
  # Stops relaying on a given local port.
  #
  def stop_tcp_relay(lport, lhost = nil)
    stop_relay(lport.to_s + (lhost || '0.0.0.0'))
  end

  #
  # Stops a relay with a given name.
  #
  def stop_relay(name)
    rv = false

    self.relay_mutex.synchronize {
      relay = self.relays[name]

      if relay
        close_relay(relay)
        rv = true
      end
    }

    rv
  end

  #
  # Enumerate each TCP relay
  #
  def each_tcp_relay(&block)
    self.relays.each_pair { |name, relay|
      next if (relay.opts['__RelayType'] != 'tcp')

      yield(
        relay.opts['LocalHost'] || '0.0.0.0',
        relay.opts['LocalPort'],
        relay.opts['PeerHost'],
        relay.opts['PeerPort'],
        relay.opts)
    }
  end

protected

  attr_accessor :relays, :relay_thread, :relay_mutex
  attr_accessor :rfds, :rev_chans

  #
  # Closes an cleans up a specific relay
  #
  def close_relay(relay)

    if relay.kind_of?(ReverseRelay)
      self.rev_chans.delete(relay.channel)
    else
      self.rfds.delete(relay.listener)
    end

    self.relays.delete(relay.name)

    begin
      relay.shutdown
      relay.close
    rescue IOError
    end
  end

  #
  # Closes a specific relay connection without tearing down the actual relay
  # itself.
  #
  def close_relay_conn(fd)
    relay = fd.relay
    ofd   = fd.other_stream

    self.rfds.delete(fd)

    begin
      if relay.on_conn_close_proc
        relay.on_conn_close_proc.call(fd)
      end

      fd.shutdown
      fd.close
    rescue IOError
    end

    if ofd
      self.rfds.delete(ofd)

      begin
        if (relay.on_conn_close_proc)
          relay.on_conn_close_proc.call(ofd)
        end

        ofd.shutdown
        ofd.close
      rescue IOError
      end
    end
  end

  #
  # Attempt to accept a new reverse connection on the given reverse
  # relay handle.
  #
  def accept_reverse_relay(rrfd)

    rfd = rrfd.accept_nonblock

    return unless rfd

    lfd = Rex::Socket::Tcp.create(
      'PeerHost'  => rrfd.relay.opts['PeerHost'],
      'PeerPort'  => rrfd.relay.opts['PeerPort'],
      'Timeout'   => 5
    )

    rfd.extend(Stream)
    lfd.extend(Stream)

    rfd.relay = rrfd.relay
    lfd.relay = rrfd.relay

    self.rfds << lfd
    self.rfds << rfd

    rfd.other_stream = lfd
    lfd.other_stream = rfd
  end

  #
  # Accepts a client connection on a local relay.
  #
  def accept_relay_conn(srvfd)
    relay = srvfd.relay

    begin
      dlog("Accepting relay client connection...", 'rex', LEV_3)

      # Accept the child connection
      lfd = srvfd.accept
      dlog("Got left side of relay: #{lfd}", 'rex', LEV_3)

      # Call the relay's on_local_connection method which should return a
      # remote connection on success
      rfd = srvfd.on_local_connection(relay, lfd)

      dlog("Got right side of relay: #{rfd}", 'rex', LEV_3)
    rescue
      wlog("Failed to get remote half of local connection on relay #{relay.name}: #{$!}", 'rex')
      lfd.close
      return
    end

    # If we have both sides, then we rock.  Extend the instances, associate
    # them with the relay, associate them with each other, and add them to
    # the list of polling file descriptors
    if lfd && rfd
      lfd.extend(Stream)
      rfd.extend(Stream)

      lfd.relay = relay
      rfd.relay = relay

      lfd.other_stream = rfd
      rfd.other_stream = lfd

      self.rfds << lfd
      self.rfds << rfd
    else
      # Otherwise, we don't have both sides, we'll close them.
      close_relay_conn(lfd)
    end
  end

  #
  # Monitors the relays for data and passes it in both directions.
  #
  def monitor_relays
    begin
      # Helps with latency
      Thread.current.priority = 2

      # See if we have any new connections on the existing reverse port
      # forward relays
      rev_chans.each do |rrfd|
        accept_reverse_relay(rrfd)
      end

      # Poll all the streams...
      begin
        socks = Rex::ThreadSafe.select(rfds, nil, nil, 0.25)
      rescue StreamClosedError => e
        dlog("monitor_relays: closing stream #{e.stream}", 'rex', LEV_3)

        # Close the relay connection that is associated with the stream
        # closed error
        if e.stream.kind_of?(Stream)
          close_relay_conn(e.stream)
        end

        dlog("monitor_relays: closed stream #{e.stream}", 'rex', LEV_3)

        next
      rescue
        elog("Error in #{self} monitor_relays select: #{$!.class} #{$!}", 'rex')
        return
      end

      # If socks is nil, go again.
      next unless socks

      # Process read-ready file descriptors, if any.
      socks[0].each { |rfd|

        # If this file descriptor is a server, accept the connection
        if (rfd.kind_of?(StreamServer))
          accept_relay_conn(rfd)
        else
          # Otherwise, it's a relay connection, read data from one side
          # and write it to the other
          begin
            # Pass the data onto the other fd, most likely writing it.
            data = rfd.sysread(65536)
            rfd.other_stream.on_other_data(data)
          # If we catch an error, close the connection
          rescue ::Exception
            elog("Error in #{self} monitor_relays read: #{$!}", 'rex')
            close_relay_conn(rfd)
          end
        end

      } if (socks[0])

    end while true
  end

end

end
end

