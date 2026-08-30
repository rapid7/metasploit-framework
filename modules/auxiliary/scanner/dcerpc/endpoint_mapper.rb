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
      'Name' => 'Endpoint Mapper Service Discovery',
      'Description' => %q{
        This module can be used to obtain information from the
        Endpoint Mapper service.
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
    ids = dcerpc_endpoint_list
    return unless ids

    name = nil
    ids.each do |id|
      next if !id[:prot]

      line = "#{id[:uuid]} v#{id[:vers]} "
      line << "#{id[:prot].upcase} "
      line << "(#{id[:port]}) " if id[:port]
      line << "(#{id[:pipe]}) " if id[:pipe]
      line << "#{id[:host]} " if id[:host]
      line << "[#{id[:note]}]" if id[:note]
      print_status(line)
      if id[:host] && (id[:host][0, 2] == '\\\\')
        name = id[:host][2..]
      end
      next unless (id[:prot].downcase == 'tcp') || (id[:prot].downcase == 'udp')

      report_service(
        host: ip,
        port: id[:port],
        proto: id[:prot].downcase,
        name: 'dcerpc',
        info: "#{id[:uuid]} v#{id[:vers]} #{id[:note]}"
      )
    end

    report_host(host: ip, name: name) if name
    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'dcerpc',
      info: "Endpoint Mapper (#{ids.length} services)"
    )
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::Rex::Proto::DCERPC::Exceptions::Fault => e
    vprint_error("#{ip}:#{rport} error: #{e}")
  rescue StandardError => e
    print_error("#{ip}:#{rport} error: #{e}")
  end
end
