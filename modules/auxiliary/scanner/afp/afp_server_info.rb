##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::AFP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apple Filing Protocol Info Enumerator',
        'Description' => %q{
          This module fetches AFP server information, including server name,
          network address, supported AFP versions, signature, machine type,
          and server flags.
        },
        'References' => [
          [ 'URL', 'https://web.archive.org/web/20130309051753/https://developer.apple.com/library/mac/#documentation/Networking/Reference/AFP_Reference/Reference/reference.html' ]
        ],
        'Author' => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run_host(ip)
    print_status("AFP #{ip} Scanning...")
    connect
    response = get_info
    report(response)
  rescue ::Timeout::Error => e
    vprint_error(e.message)
  rescue ::Rex::ConnectionError, ::IOError, ::Errno::ECONNRESET, ::Errno::ENOPROTOOPT => e
    vprint_error(e.message)
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError
    print_error("AFP #{rhost}:#{rport} #{$ERROR_INFO.class} #{$ERROR_INFO}")
    raise $ERROR_INFO
  ensure
    disconnect
  end

  def report(response)
    report_info = "AFP #{rhost}:#{rport} Server Name: #{response[:server_name]} \n" \
                  "AFP #{rhost}:#{rport}  Server Flags: \n" +
                  format_flags_report(response[:server_flags]) +
                  "AFP #{rhost}:#{rport}  Machine Type: #{response[:machine_type]} \n" \
                  "AFP #{rhost}:#{rport}  AFP Versions: #{response[:versions].join(', ')} \n" \
                  "AFP #{rhost}:#{rport}  UAMs: #{response[:uams].join(', ')}\n" \
                  "AFP #{rhost}:#{rport}  Server Signature: #{response[:signature]}\n" \
                  "AFP #{rhost}:#{rport}  Server Network Address: \n" +
                  format_addresses_report(response[:network_addresses]) +
                  "AFP #{rhost}:#{rport}   UTF8 Server Name: #{response[:utf8_server_name]}"

    lines = "AFP #{rhost}:#{rport}:#{rport} AFP:\n#{report_info}"

    lines.split(/\n/).each do |line|
      print_status(line)
    end

    report_note(
      host: datastore['RHOST'],
      proto: 'tcp',
      port: datastore['RPORT'],
      type: 'afp_server_info',
      data: { server_info: response }
    )

    report_service(
      host: datastore['RHOST'],
      port: datastore['RPORT'],
      proto: 'tcp',
      name: 'afp',
      info: "AFP name: #{response[:utf8_server_name]}, Versions: #{response[:versions].join(', ')}"
    )
  end

  def format_flags_report(parsed_flags)
    report = ''
    parsed_flags.each do |flag, val|
      report << "AFP #{rhost}:#{rport}     *  #{flag}: #{val} \n"
    end
    return report
  end

  def format_addresses_report(parsed_network_addresses)
    report = ''
    parsed_network_addresses.each do |val|
      report << "AFP #{rhost}:#{rport}     *  #{val} \n"
    end
    return report
  end
end
