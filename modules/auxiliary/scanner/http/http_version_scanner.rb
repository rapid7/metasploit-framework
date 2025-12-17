class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Simple TCP Banner Grabber',
      'Description' => %q{
        This module connects to a specified port and grabs the banner 
        (the welcome message) sent by the service.
      },
      'Author'      => [ 'Apeksh Athrey' ],
      'License'     => MSF_LICENSE
    ))
    register_options(
      [
        Opt::RPORT(80)
      ])
  end
  def run_host(ip)
    begin
      connect
      banner = sock.get_once(-1, 10)
      if banner
        print_good("#{ip}:#{rport} - BANNER FOUND: #{banner.strip}")

        report_service(:host => ip, :port => rport, :name => "custom_banner", :info => banner)
      else
        print_status("#{ip}:#{rport} - Connected, but no banner received.")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout

    ensure
      disconnect
    end
  end
end
