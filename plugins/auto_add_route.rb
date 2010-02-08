module Msf
class Plugin::AutoAddRoute < Msf::Plugin
	include Msf::SessionEvent
	def name; 'auto_add_route'; end
	def on_session_open(session)
		return if not session.type == 'meterpreter'
		session.load_stdapi
		session.net.config.each_route { |route|
			# Remove multicast and loopback interfaces
			next if route.subnet =~ /^(224\.|127\.)/
			next if route.subnet == '0.0.0.0'
			next if route.netmask == '255.255.255.255'
			if not Rex::Socket::SwitchBoard.route_exists?(route.subnet, route.netmask)
				print_status("AutoAddRoute: Routing new subnet #{route.subnet}/#{route.netmask} through session #{session.sid}")
				Rex::Socket::SwitchBoard.add_route(route.subnet, route.netmask, session)
			end
		}
	end

	def initialize(framework, opts)
		super
		self.framework.events.add_session_subscriber(self)
	end

	def cleanup
		self.framework.events.remove_session_subscriber(self)
	end

end
end

