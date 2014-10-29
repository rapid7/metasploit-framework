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
          Opt::RPORT(2000),
      ], self.class)
    register_advanced_options(
      [
          OptString.new('PROTO_TYPE',   [ true, "Device Type (e.g. SIP,SEP)", "SEP"]),
          OptString.new('LINE',   [ false, "Source line (e.g. 1,2)"]),
          OptString.new('DEVICE_IP',   [ false, "IP address of the device for spoofing"]),
          OptString.new('CISCOCLIENT',   [ true, "Cisco software type (ipphone,cipc)","cipc"]),
          OptString.new('CAPABILITIES',   [ false, "Capabilities of the device (e.g. Router, Host, Switch)", "Host"]),
          OptString.new('PLATFORM',   [ false, "Platform of the device", "Cisco IP Phone 7975"]),
          OptString.new('SOFTWARE',   [ false, "Software of the device", "SCCP75.9-3-1SR2-1S"]),
          OptString.new('DEBUG',   [ false, "Debug level" ]),
      ], self.class)
  end

  def run
    #options from the user
    if datastore['MAC'] and datastore['TARGET']
      mac = datastore['MAC'].upcase
    else
      raise RuntimeError ,'MAC and TARGET should be defined'
    end
    line=datastore['LINE'] || 1
    target=datastore['TARGET']
    client=datastore['CISCOCLIENT'].downcase
    capabilities=datastore['CAPABILITIES'] || "Host"
    platform=datastore['PLATFORM'] || "Cisco IP Phone 7975"
    software=datastore['SOFTWARE'] || "SCCP75.9-3-1SR2-1S"
    if datastore['DEVICE_IP']
      device_ip=datastore['DEVICE_IP']
    else
      device_ip=Rex::Socket.source_address(datastore['RHOST'])
    end
    device="#{datastore['PROTO_TYPE']}#{mac.gsub(":","")}"

    #Skinny Call Test
    begin
      connect

      #Registration
      register(sock,device,device_ip,client,mac,false)
      #Call
      call(sock,line,target)

      disconnect
    rescue Rex::ConnectionError => e
      print_error("Connection failed: #{e.class}: #{e}")
      return nil
    end
  end

end
