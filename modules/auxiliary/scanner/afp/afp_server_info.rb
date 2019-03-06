##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::AFP

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Apple Filing Protocol Info Enumerator',
      'Description'  => %q{
        This module fetches AFP server information, including server name,
        network address, supported AFP versions, signature, machine type,
        and server flags.
      },
      'References'     =>
        [
          [ 'URL', 'https://developer.apple.com/library/mac/documentation/Networking/Reference/AFP_Reference/Reference/reference.html' ]
        ],
      'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
      'License'      => MSF_LICENSE
    ))
  end

  def run_host(ip)
    print_status("AFP #{ip} Scanning...")
    begin
      connect
      response = get_info
      report(response)
    rescue ::Timeout::Error
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError, ::IOError, ::Errno::ECONNRESET, ::Errno::ENOPROTOOPT
    rescue ::Exception
      raise $!
      print_error("AFP #{rhost}:#{rport} #{$!.class} #{$!}")
    ensure
      disconnect
    end
  end

  def report(response)
    report_info = "AFP #{rhost}:#{rport} Server Name: #{response[:server_name]} \n" +
    "AFP #{rhost}:#{rport}  Server Flags: \n" +
    format_flags_report(response[:server_flags]) +
    "AFP #{rhost}:#{rport}  Machine Type: #{response[:machine_type]} \n" +
    "AFP #{rhost}:#{rport}  AFP Versions: #{response[:versions].join(', ')} \n" +
    "AFP #{rhost}:#{rport}  UAMs: #{response[:uams].join(', ')}\n" +
    "AFP #{rhost}:#{rport}  Server Signature: #{response[:signature]}\n" +
    "AFP #{rhost}:#{rport}  Server Network Address: \n" +
    format_addresses_report(response[:network_addresses]) +
    "AFP #{rhost}:#{rport}   UTF8 Server Name: #{response[:utf8_server_name]}"


    lines = "AFP #{rhost}:#{rport}:#{rport} AFP:\n#{report_info}"

    lines.split(/\n/).each do |line|
      print_status(line)
    end

    report_note(:host => datastore['RHOST'],
      :proto => 'tcp',
      :port => datastore['RPORT'],
      :type => 'afp_server_info',
      :data => response)

      report_service(
        :host => datastore['RHOST'],
        :port => datastore['RPORT'],
        :proto => 'tcp',
        :name => "afp",
        :info => "AFP name: #{response[:utf8_server_name]}, Versions: #{response[:versions].join(', ')}"
      )

  end

  def format_flags_report(parsed_flags)
    report = ''
    parsed_flags.each do |flag, val|
      report << "AFP #{rhost}:#{rport}     *  #{flag}: #{val.to_s} \n"
    end
    return report
  end

  def format_addresses_report(parsed_network_addresses)
    report = ''
    parsed_network_addresses.each do |val|
      report << "AFP #{rhost}:#{rport}     *  #{val.to_s} \n"
    end
    return report
  end
end
