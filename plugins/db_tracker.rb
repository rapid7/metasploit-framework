module Msf
  ###
  #
  # This class hooks all socket calls and updates the database with
  # data gathered from the connection parameters
  #
  ###

  class Plugin::DB_Tracer < Msf::Plugin

    ###
    #
    # This class implements a socket communication tracker
    #
    ###
    class DBTracerEventHandler
      include Rex::Socket::Comm::Events

      def on_before_socket_create(comm, param); end

      def on_socket_created(_comm, sock, param)
        # Ignore local listening sockets
        return if !sock.peerhost

        if ((sock.peerhost != '0.0.0.0') && sock.peerport)

          # Ignore sockets that didn't set up their context
          # to hold the framework in 'Msf'
          return if !param.context['Msf']

          host = param.context['Msf'].db.find_or_create_host(host: sock.peerhost, state: Msf::HostState::Alive)
          return if !host

          param.context['Msf'].db.report_service(host: host, proto: param.proto, port: sock.peerport)
        end
      end
    end

    def initialize(framework, opts)
      super

      if !framework.db.active
        raise PluginLoadError, 'The database backend has not been initialized'
      end

      framework.plugins.each do |plugin|
        if plugin.instance_of?(Msf::Plugin::DB_Tracer)
          raise PluginLoadError, 'This plugin should not be loaded more than once'
        end
      end

      @eh = DBTracerEventHandler.new
      Rex::Socket::Comm::Local.register_event_handler(@eh)
    end

    def cleanup
      Rex::Socket::Comm::Local.deregister_event_handler(@eh)
    end

    def name
      'db_tracker'
    end

    def desc
      'Monitors socket calls and updates the database backend'
    end

  end
end
