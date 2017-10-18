##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Endpoint Mapper Service Discovery',
      'Description' => %q{
        This module can be used to obtain information from the
        Endpoint Mapper service.
      },
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOST')

    register_options(
      [
        Opt::RPORT(135)
      ])
  end

  # Obtain information about a single host
  def run_host(ip)
    begin

      ids = dcerpc_endpoint_list()
      return if not ids
      name = nil
      ids.each do |id|
        next if not id[:prot]
        line = "#{id[:uuid]} v#{id[:vers]} "
        line << "#{id[:prot].upcase} "
        line << "(#{id[:port]}) " if id[:port]
        line << "(#{id[:pipe]}) " if id[:pipe]
        line << "#{id[:host]} " if id[:host]
        line << "[#{id[:note]}]" if id[:note]
        print_status(line)
        if (id[:host] and id[:host][0,2] == "\\\\")
          name = id[:host][2..-1]
        end
        if id[:prot].downcase == "tcp" or id[:prot].downcase == "udp"
          report_service(
            :host => ip,
            :port => id[:port],
            :proto => id[:prot].downcase,
            :name => "dcerpc",
            :info => "#{id[:uuid]} v#{id[:vers]} #{id[:note]}"
          )
        end
      end
      report_host(:host => ip, :name => name) if name
      report_service(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :name => "dcerpc",
        :info => "Endpoint Mapper (#{ids.length} services)"
      )

    rescue ::Interrupt
      raise $!
    rescue ::Rex::Proto::DCERPC::Exceptions::Fault
    rescue ::Exception => e
      print_error("#{ip}:#{rport} error: #{e}")
    end
  end


end
