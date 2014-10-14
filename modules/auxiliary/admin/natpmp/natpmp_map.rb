##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::NATPMP
  include Rex::Proto::NATPMP

  def initialize
    super(
      'Name'        => 'NAT-PMP Port Mapper',
      'Description' => 'Map (forward) TCP and UDP ports on NAT devices using NAT-PMP',
      'Author'      => 'Jon Hart <jhart[at]spoofed.org>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptPort.new('EXTERNAL_PORT', [true, 'The external port to foward from']),
        OptPort.new('INTERNAL_PORT', [true, 'The internal port to forward to']),
        OptInt.new('LIFETIME', [true, "Time in ms to keep this port forwarded", 3600000]),
        OptEnum.new('PROTOCOL', [true, "Protocol to forward", 'TCP', %w(TCP UDP)]),
      ],
      self.class
    )
  end

  def run_host(host)
    begin

      udp_sock = Rex::Socket::Udp.create({
        'LocalHost' => datastore['CHOST'] || nil,
        'Context'   => {'Msf' => framework, 'MsfExploit' => self}
      })
      add_socket(udp_sock)

      # new
      external_address = get_external_address(udp_sock, host, datastore['RPORT']) || host
      actual_ext_port = map_port(udp_sock, host, datastore['RPORT'], datastore['INTERNAL_PORT'], datastore['EXTERNAL_PORT'], Rex::Proto::NATPMP.const_get(datastore['PROTOCOL']), datastore['LIFETIME'])

      if actual_ext_port
        map_target = Rex::Socket.source_address(host)
        if (datastore['EXTERNAL_PORT'] != actual_ext_port)
          print_status(	"#{external_address} " +
                  "#{datastore['EXTERNAL_PORT']}/#{datastore['PROTOCOL']} -> #{map_target} " +
                  "#{datastore['INTERNAL_PORT']}/#{datastore['PROTOCOL']} couldn't be forwarded")
        end
        print_status(	"#{external_address} " +
                "#{actual_ext_port}/#{datastore['PROTOCOL']} -> #{map_target} " +
                "#{datastore['INTERNAL_PORT']}/#{datastore['PROTOCOL']} forwarded")

        # report NAT-PMP as being open
        report_service(
          :host   => host,
          :port   => datastore['RPORT'],
          :proto  => 'udp',
          :name  => 'natpmp',
          :state => Msf::ServiceState::Open
        )
      end
    rescue ::Interrupt
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
      nil
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e.backtrace}")
    end
  end

end
