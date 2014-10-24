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
      'Name'				=> 'Viproy Cisco Skinny Register Analyser',
      'Description' => 'This module helps to develop register tests for Skinny',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     =>  MSF_LICENSE,
    )
    register_options(
      [
          OptString.new('MAC',   [ false, "MAC Address"]),
          OptString.new('MACFILE',   [ false, "Input file contains MAC Addresses"]),
          Opt::RPORT(2000),
      ], self.class)

    register_advanced_options(
      [
          OptString.new('PROTO_TYPE',   [ true, "Device Type (e.g. SIP,SEP)", "SEP"]),
          OptString.new('DEVICE_IP',   [ false, "IP address of the device"]),
          OptString.new('CISCOCLIENT',   [ true, "Cisco software type (ipphone,cipc)","cipc"]),
          OptString.new('CAPABILITIES',   [ false, "Capabilities of the device (e.g. Router, Host, Switch)", "Host"]),
          OptString.new('PLATFORM',   [ false, "Platform of the device", "Cisco IP Phone 7975"]),
          OptString.new('SOFTWARE',   [ false, "Software of the device", "SCCP75.9-3-1SR2-1S"]),
          OptString.new('DEBUG',   [ false, "Debug level" ]),
      ], self.class)
  end

  def run
    #options from the user
    capabilities=datastore['CAPABILITIES'] || "Host"
    platform=datastore['PLATFORM'] || "Cisco IP Phone 7975"
    software=datastore['SOFTWARE'] || "SCCP75.9-3-1SR2-1S"
    raise RuntimeError ,'MAC or MACFILE should be defined' unless datastore['MAC'] or datastore['MACFILE']
    if datastore['MACFILE']
      macs = macfileimport(datastore['MACFILE'])
    else
      macs = []
    end
    macs << datastore['MAC'].upcase if datastore['MAC']
    client=datastore['CISCOCLIENT'].downcase
    if datastore['DEVICE_IP']
      device_ip=datastore['DEVICE_IP']
    else
      device_ip=Rex::Socket.source_address(datastore['RHOST'])
    end

    #Skinny Registration Test
    macs.each do |mac|
      device="#{datastore['PROTO_TYPE']}#{mac.gsub(":","")}"
      begin
        connect
        register(sock,device,device_ip,client,mac)
        disconnect
      rescue Rex::ConnectionError => e
        print_error("Connection failed: #{e.class}: #{e}")
        return nil
      end
    end
  end
end
