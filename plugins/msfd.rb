#
# $Id$
#
# This plugin provides an msf daemon interface that spawns a listener on a
# defined port (default 55554) and gives each connecting client its own
# console interface.  These consoles all share the same framework instance.
# Be aware that the console instance that spawns on the port is entirely
# unauthenticated, so realize that you have been warned.
#
# $Revision$
#

module Msf

###
#
# This class implements the msfd plugin interface.
#
###
class Plugin::Msfd < Msf::Plugin

  #
  # The default local hostname that the server listens on.
  #
  DefaultHost = "127.0.0.1"

  #
  # The default local port that the server listens on.
  #
  DefaultPort = 55554

  #
  # Initializes the msfd plugin.  The following options are supported in the
  # hash by this plugin:
  #
  # ServerHost
  #
  # 	The local hostname to listen on for connections.  The default is
  # 	127.0.0.1.
  #
  # ServerPort
  #
  # 	The local port to listen on for connections.  The default is 55554.
  #
  # SSL
  #
  #	Use SSL
  #
  # RunInForeground
  #
  # 	Instructs the plugin to now execute the daemon in a worker thread and to
  # 	instead allow the caller to manage executing the daemon through the
  # 	``run'' method.
  #
  # HostsAllowed
  #
  #	List of hosts (in NBO) allowed to use msfd
  #
  # HostsDenied
  #
  #	List of hosts (in NBO) not allowed to use msfd
  #
  def initialize(framework, opts)
    super

    # Start listening for connections.
    self.server	= Rex::Socket::TcpServer.create(
      'LocalHost' => opts['ServerHost'] || DefaultHost,
      'LocalPort' => opts['ServerPort'] || DefaultPort,
      'SSL'       => opts['SSL'])

    # If the run in foreground flag is not specified, then go ahead and fire
    # it off in a worker thread.
    if (opts['RunInForeground'] != true)
      Thread.new {
        run(opts)
      }
    end
  end

  #
  # Returns 'msfd'
  #
  def name
    "msfd"
  end

  #
  # Returns the msfd plugin description.
  #
  def desc
    "Provides a console interface to users over a listening TCP port."
  end

  #
  # Runs the msfd plugin by blocking on new connections and then spawning
  # threads to handle the console interface for each client.
  #
  def run(opts={})
    while true
      client = server.accept

      addr = Rex::Socket.resolv_nbo(client.peerhost)

      if opts['HostsAllowed'] and
        not opts['HostsAllowed'].find { |x| x == addr }
        client.close
        next
      end

      if opts['HostsDenied'] and
        opts['HostsDenied'].find { |x| x == addr }
        client.close
        next
      end
      msg = "Msfd: New connection from #{client.peerhost}"
      ilog(msg, 'core')
      print_status(msg)

      # Spawn a thread for the client connection
      Thread.new(client) { |cli|
        begin
          Msf::Ui::Console::Driver.new(
            Msf::Ui::Console::Driver::DefaultPrompt,
            Msf::Ui::Console::Driver::DefaultPromptChar,
            'Framework'   => framework,
            'LocalInput'  => Rex::Ui::Text::Input::Socket.new(cli),
            'LocalOutput' => Rex::Ui::Text::Output::Socket.new(cli),
            'AllowCommandPassthru' => false,
            'DisableBanner' => opts['DisableBanner'] ? true : false).run
        rescue
          elog("Msfd: Client error: #{$!}\n\n#{$@.join("\n")}", 'core')
        ensure
          msg = "Msfd: Closing client connection with #{cli.peerhost}"
          ilog(msg, 'core')
          print_status(msg)
          begin
            cli.shutdown
            cli.close
          rescue IOError
          end
        end
      }
    end
  end

  #
  # Closes the listener service.
  #
  def cleanup
    ilog("Msfd: Shutting down server", 'core')
    self.server.close
  end

protected

  #
  # The listening socket instance.
  #
  attr_accessor :server

end

end

