##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Skinny
  include Msf::Exploit::Remote::Tcp

  def initialize
    super(
      'Name'				=> 'Viproy Cisco Call Analyser',
      'Description' => 'This module helps to test call features for Skinny',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     =>  MSF_LICENSE,
    )
    register_options(
      [
        OptString.new('MAC',   [ true, "MAC Address"]),
        OptString.new('TARGET',   [ true, "Target number (e.g. 986100)"]),
        Opt::RPORT(2000)
      ], self.class)
    register_advanced_options(
      [
        OptInt.new('LINE', [true, "Source line (e.g. 1,2)", 1])
      ], self.class)
  end

  def run
    line = datastore['LINE']
    target = datastore['TARGET']
    client = datastore['CISCOCLIENT'].downcase
    capabilities = datastore['CAPABILITIES']
    platform = datastore['PLATFORM']
    software = datastore['SOFTWARE']
    if datastore['DEVICE_IP']
      device_ip = datastore['DEVICE_IP']
    else
      device_ip = Rex::Socket.source_address(datastore['RHOST'])
    end
    device = "#{datastore['PROTO_TYPE']}#{mac.gsub(":", "")}"

    # Skinny Call Test
    begin
      connect

      # Registration
      register(sock, device, device_ip, client, mac, false)
      # Call
      call(sock, line, target)

      disconnect
    rescue Rex::ConnectionError => e
      print_error("Connection failed: #{e.class}: #{e}")
      return nil
    end
  end
end
