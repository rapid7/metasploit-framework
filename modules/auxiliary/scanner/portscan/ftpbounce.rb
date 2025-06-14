##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Order is important here
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Ftp

  def initialize
    super(
      'Name'        => 'FTP Bounce Port Scanner',
      'Description' => %q{
        Enumerate TCP services via the FTP bounce PORT/LIST
        method.
      },
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
      OptAddress.new('BOUNCEHOST', [true, "FTP relay host"]),
      OptPort.new('BOUNCEPORT', [true, "FTP relay port", 21]),
      OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
      OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.", 0])
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
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    jitter_value = datastore['JITTER'].to_i
    if jitter_value < 0
      raise Msf::OptionValidateError.new(['JITTER'])
    end

    delay_value = datastore['DELAY'].to_i
    if delay_value < 0
      raise Msf::OptionValidateError.new(['DELAY'])
    end

    return if not connect_login

    ports.each do |port|
      # Clear out the receive buffer since we're heavily dependent
      # on the response codes.  We need to do this between every
      # port scan attempt unfortunately.
      while true
        r = sock.get_once(-1, 0.25)
        break if not r or r.empty?
      end

      begin

        # Add the delay based on JITTER and DELAY if needs be
        add_delay_jitter(delay_value,jitter_value)

        host = (ip.split('.') + [port / 256, port % 256]).join(',')
        resp = send_cmd(["PORT", host])

        if resp =~ /^5/
          #print_error("Got error from PORT to #{ip}:#{port}")
          next
        elsif not resp
          next
        end

        resp = send_cmd(["LIST"])

        if resp =~ /^[12]/
          print_good(" TCP OPEN #{ip}:#{port}")
          report_service(:host => ip, :port => port)
        end
      rescue ::Exception
        print_error("Unknown error: #{$!}")
      end
    end
  end
end
