##
# This module requires Metasploit: https://metasploit.com/download
# Current Source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  # Include network scanner and TCP communication mixins
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'MySQL Server Active IP Detector',
      'Description' => 'Discover active IP addresses running MySQL services by checking the TCP port 3306.',
      'Author'      => [ '1nf1n7y' ],
      'License'     => MSF_LICENSE
    )

    # Register the default MySQL port (3306)
    register_options(
      [
        Opt::RPORT(3306)
      ]
    )
  end

  # This method is automatically called for each target IP in the specified range (RHOSTS)
  def run_host(ip)
    begin
      # Attempt to open a quick TCP connection with the target
      # Use a short timeout to ensure efficient scanning performance
      connect(true, { 'ConnectTimeout' => 2.0 })
      
      # If connection succeeds without errors, the port is open and the service is running
      print_good("#{ip} - SUCCESS: MySQL service is running on port #{rport}")
      
      # Report and log the active service into the Metasploit database
      report_service(:host => ip, :port => rport, :name => 'mysql')
      
    rescue ::Rex::ConnectionRefused
      # Triggered if the target actively refuses the connection (port is closed)
      vprint_status("#{ip} - Connection refused (Port #{rport} is closed).")
    rescue ::Rex::ConnectionTimeout
      # Triggered if the connection times out (host is down or filtered by a firewall)
      vprint_status("#{ip} - Connection timed out.")
    rescue ::Exception => e
      # Catch any other unexpected exceptions
      vprint_error("#{ip} - Error: #{e.message}")
    ensure
      # Ensure the connection is always properly closed to free system resources
      disconnect
    end
  end
end