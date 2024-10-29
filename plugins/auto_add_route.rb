module Msf
  class Plugin::AutoAddRoute < Msf::Plugin
    include Msf::SessionEvent
    def name
      'auto_add_route'
    end

    def desc
      'Adds routes for any new subnets whenever a session opens'
    end

    def on_session_open(session)
      return if session.type != 'meterpreter'

      session.load_stdapi
      sb = Rex::Socket::SwitchBoard.instance
      session.net.config.each_route do |route|
        # Remove multicast and loopback interfaces
        next if route.subnet =~ /^(224\.|127\.)/
        next if route.subnet == '0.0.0.0'
        next if route.netmask == '255.255.255.255'

        if !sb.route_exists?(route.subnet, route.netmask)
          print_status("AutoAddRoute: Routing new subnet #{route.subnet}/#{route.netmask} through session #{session.sid}")
          sb.add_route(route.subnet, route.netmask, session)
        end
      end
    end

    def initialize(framework, opts)
      super
      self.framework.events.add_session_subscriber(self)
    end

    def cleanup
      framework.events.remove_session_subscriber(self)
    end

  end
end
