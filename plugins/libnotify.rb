###
#
# This plugin hooks all session creation and db events
# and send desktop notifications using notify-send command.
#
###

module Msf

class Plugin::EventLibnotify < Msf::Plugin
  include Msf::SessionEvent
  include Msf::DatabaseEvent

  def initialize(framework, opts)
    super

    @bin = opts[:bin] || opts['bin'] || `which notify-send`.chomp
    @bin_opts = opts[:opts] || opts['opts'] || '-a Metasploit'

    raise 'libnotify not found' if @bin.empty?

    self.framework.events.add_session_subscriber(self)
    self.framework.events.add_db_subscriber(self)
  end

  def notify_send(urgency, title, message)
    system("#{@bin} #{@bin_opts} -u #{urgency} '#{title}' '#{message}'")
  end

  def on_session_open(session)
    notify_send('normal', 'Got Shell!',
                "New Session: #{session.sid}\nIP: #{session.session_host}\nPeer: #{session.tunnel_peer}\n"\
                "Platform: #{session.platform}\nType: #{session.type}")
  end

  def on_session_close(session, reason='')
    notify_send('normal', 'Connection closed',
                "Session:#{session.sid} Type:#{session.type} closed.\n#{reason}")
  end

  def on_session_fail(reason='')
    notify_send('critical', 'Session Failure!', reason)
  end

  def on_db_host(host)
    notify_send('normal', 'New host',
                "Addess: #{host.address}\nOS: #{host.os_name}")
  end

  def on_db_host_state(host, ostate)
    notify_send('normal', "Host #{host.address} changed",
                "OS: #{host.os_name}\nNb Services: #{host.service_count}\nNb vulns: #{host.vuln_count}\n")
  end

  def on_db_service(service)
    notify_send('normal', 'New service',
                "New service: #{service.host.address}:#{service.port}")
  end

  def on_db_service_state(service, port, ostate)
    notify_send('normal', "Service #{service.host.address}:#{service.port} changed",
                "Name: #{service.name}\nState: #{service.state}\nProto: #{service.proto}\nInfo: #{service.info}")
  end

  def on_db_vuln(vuln)
    notify_send('critical', "New vulnerability on #{vuln.host.address}:#{vuln.service ? vuln.service.port : '0'}",
                "Vuln: #{vuln.name}\nInfos: #{vuln.info}")
  end

  def on_db_ref(ref)
    notify_send('normal', 'New ref', "Reference #{ref.name} added in database.")
  end

  def on_db_client(client)
    notify_send('critical', 'New client', "New client connected: #{client.ua_string}")
  end

  def cleanup
    self.framework.events.remove_session_subscriber(self)
    self.framework.events.remove_db_subscriber(self)
  end

  def name
    'libnotify'
  end

  def desc
    'Send desktop notification with libnotify on sessions & db events'
  end
end
end
