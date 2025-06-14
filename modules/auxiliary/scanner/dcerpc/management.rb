##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Remote Management Interface Discovery',
      'Description' => %q{
        This module can be used to obtain information from the Remote
        Management Interface DCERPC service.
      },
      'Author' => 'hdm',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        Opt::RPORT(135)
      ]
    )
  end

  # Obtain information about a single host
  def run_host(ip)
    ids = dcerpc_mgmt_inq_if_ids(rport)
    return unless ids

    ids.each do |id|
      print_status("UUID #{id[0]} v#{id[1]}")

      reportdata = ''

      stats = dcerpc_mgmt_inq_if_stats(rport)
      if stats
        print_status("\t stats: " + stats.map { |i| '0x%.8x' % i }.join(', '))
        reportdata << 'stats: ' + stats.map { |i| '0x%.8x' % i }.join(', ') + ' '
      end

      live = dcerpc_mgmt_is_server_listening(rport)
      if live
        print_status("\t listening: %.8x" % live)
        # reportdata << "listening: %.8x" % live + " "
      end

      dead = dcerpc_mgmt_stop_server_listening(rport)
      if dead
        print_status("\t killed: %.8x" % dead)
        # reportdata << "killed: %.8x" % dead + " "
      end

      princ = dcerpc_mgmt_inq_princ_name(rport)
      if princ
        print_status("\t name: #{princ.unpack('H*')[0]}")
        # reportdata << "name: #{princ.unpack("H*")[0]}"
      end

      report_note(
        host: ip,
        proto: 'tcp',
        port: datastore['RPORT'],
        type: "DCERPC UUID #{id[0]} v#{id[1]}",
        data: { report_data: reportdata }
      )
    end
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("Error: #{e}")
  end
end
