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

        Note: Per RFC 2577, a compliant FTP server should refuse PORT commands that
        target privileged ports (<= 1023/TCP), so those ports may not be scannable
        via FTP bounce even on an otherwise vulnerable relay.
      },
      'Author' => 'kris katterjohn',
      'License' => MSF_LICENSE
    )

    register_options([
      OptAddressRange.new('RHOSTS', [true, 'The host(s) to scan via BOUNCEHOST (FTP relay)']), # Overwrite the mixin default value
      OptString.new('PORTS', [true, 'Ports to scan (e.g. 22-25,80,110-900)', '1024-10000']),
      OptAddress.new('BOUNCEHOST', [true, 'FTP relay host']),
      OptPort.new('BOUNCEPORT', [true, 'FTP relay port', 21]),
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

  def run_host(ip)
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    if ports.empty?
      raise Msf::OptionValidateError, ['PORTS']
    end

    jitter_value = datastore['JITTER'].to_i
    if jitter_value < 0
      raise Msf::OptionValidateError, ['JITTER']
    end

    delay_value = datastore['DELAY'].to_i
    if delay_value < 0
      raise Msf::OptionValidateError, ['DELAY']
    end

    connected = connect_login

    unless connected
      print_error("Could not authenticate to relay #{rhost}:#{rport} (check FTPUSER/FTPPASS)")
      return
    end

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
          vprint_error("#{rhost}:#{rport} -> #{ip}:#{port}: PORT rejected -- #{resp.strip}")
          next
        elsif !resp
          print_error("#{rhost}:#{rport} -> #{ip}:#{port}: No response!")
          next
        end

        resp = send_cmd(['LIST'])

        if resp =~ /^[12]/
          print_good(" TCP OPEN #{ip}:#{port}")
          report_service(host: ip, port: port, info: "Discovered via FTP bounce from #{rhost}:#{rport}")
        else
          vprint_warning("#{rhost}:#{rport} -> #{ip}:#{port}: LIST -- #{resp.strip}")
        end
      rescue ::StandardError
        print_error("Unknown error: #{$ERROR_INFO}")
      end
    end
  end
end
