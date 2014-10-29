##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module Msf
  module Auxiliary::Skinny
    attr_accessor :listen_addr, :listen_port, :context
    attr_accessor :sock, :thread, :dest_addr, :dest_port, :proto, :vendor, :macaddress
    attr_accessor :prxclient_port, :prxclient_ip, :client_port, :client_ip
    attr_accessor :prxserver_port, :prxserver_ip, :server_port, :server_ip

    def initialize
      super
      register_advanced_options(
        [
          OptString.new('PROTO_TYPE', [true, 'Device Type (e.g. SIP,SEP)', 'SEP']),
          OptString.new('DEVICE_IP',  [false, 'IP address of the device for spoofing']),
          OptEnum.new('CISCOCLIENT',  [true, 'Cisco software type', %w(ipphone cipc), 'cipc']),
          OptString.new('CAPABILITIES', [false, 'Capabilities of the device (e.g. Router, Host, Switch)', 'Host']),
          OptString.new('PLATFORM', [false, 'Platform of the device', 'Cisco IP Phone 7975']),
          OptString.new('SOFTWARE', [false, 'Software of the device', 'SCCP75.9-3-1SR2-1S']),
          OptBool.new('DEBUG', [false, 'Debug level', false ])
        ], self.class)
    end

    def mac
      format_mac(datastore['MAC'])
    end

    # Formats the provided MAC into a consistent form
    def format_mac(mac)
      if mac =~ /^[a-f0-9]{12}$/i
        parts = mac.scan(/../)
      else
        parts = mac.split(/[:\-]/)
      end
      if parts.size != 6 || parts.any? { |p| p !~ /^[a-f0-9]{1,2}$/i }
        raise ArgumentError, "#{mac} is not a valid MAC"
      end
      parts.map { |p| p.rjust(2, '0') }.join(':').upcase
    end

    def register(sock, device, device_ip, client, mac, configinfo = true)
      # Register request
      sock.put(prep_register(device, device_ip, client))
      print_status("Register request sent for #{device}")

      retry_limit = 3
      retries = 0
      while true
        # Auto-registration enabled systems need extra 6 sec
        # Retrieving the response from the socket
        responses = getresponse
        if responses.empty?
          retries += 1
          if retries > retry_limit
            print_error("Register request timed-out.")
            return nil
          else
            vprint_status("Retry #{retries} of #{retry_limit} for register request")
          end
        else
          break
        end
      end

      responses.each do|response|
        r, m, l = response
        case r
        when "error"
          print_error("Connection error : #{m}")
          return nil
        when "RegisterAckMessage"
          print_good("#{mac} MAC address is registered on #{rhost}")
        when "RegisterRejectMessage"
          print_error("#{mac} MAC address is not registered on #{rhost}")
          return nil
        when "Reset"
          # Re-Register request
          sock.put(prep_register(device, device_ip, client))
          print_status("Re-Register request sent for #{device}")
        end
      end

      # Capabilities response
      sock.put(prep_capabilitiesres)
      vprint_status("Capabilities response sent for #{device}")

      # IPPort request
      sock.put(prep_ipport)
      vprint_status("IP Port request sent for #{device}")

      # Button template request
      sock.put(prep_buttontemplatereq)
      vprint_status("Button template request sent for #{device}")

      # SoftKey template request
      sock.put(prep_softkeytemplatereq)
      vprint_status("SoftKey template request sent for #{device}")

      # SoftKey set request
      sock.put(prep_softkeysetreq)
      vprint_status("SoftKey set request sent for #{device}")

      # Obtain configuration data
      sock.put(prep_configstatreq)
      print_status("Configuration request sent for #{device}")

      # retrieving responses for the configuration
      configstatrecevied = false
      c = 0
      until configstatrecevied
        print_debug("Config status is looping") if datastore["DEBUG"] == true
        # Retrieving the response from the socket
        responses = getresponse

        responses.each do|response|
          r, m, l = response
          case r
          when "error"
            print_error("#{mac} configuration couldn't retrieved from #{rhost}")
            print_error("Error is #{m}")
            return nil
            break
          when /ConfigStatMessage/
            print_good("The following is the configuration for #{mac}") if configinfo
            configstatrecevied = true
            getconfiguration(r, m, l, configinfo)
            return
          end
        end
        c += 1 if responses == []
        if c == 3
          print_error("Config information couldn't retrieve.")
          return nil
        end
      end
    end

    def call(sock, line, target)
      # Sending Off Hook request
      sock.put(prep_offhook(line, 0))
      print_status("Off Hook request sent for line #{line}")

      # Retrieving the response from the socket
      starttonereceived = false
      c = 0
      while c < 3 && !starttonereceived
        responses = getresponse

        # Retrieving the start tone response from the socket
        responses.each do|response|
          r, m, l = response
          if r == "StartToneMessage"
            starttonereceived = true
            @callidentifier = m.split("\t")[0].split(": ")[1]
            vprint_status("Call identifier is #{@callidentifier}")
          end
        end
        c += 1
      end

      # Dialing the number
      target.each_char do |n|
        sock.put(prep_keypadbutton(n, line, @callidentifier))
      end
      print_status("Numbers dialed for line #{line}")

      # Retrieving the response from the socket
      callresreceived = false
      c = 0
      while c < 3 && !callresreceived
        responses = getresponse

        responses.each do|response|
          r, m, l = response
          case r
          when "CallInfoMessage"
            callresreceived = true
            print_good("Call is successful, #{target} is ringing.")
            return nil
          when "CM5CallInfoMessage"
            callresreceived = true
            print_good("Call is successful, #{target} is ringing.")
            return nil
          when "StartToneMessage"
            callresreceived = true
            print_error("Call failed, the target number is not available.")
            return nil
          end
        end
        c += 1
        if c == 3
          print_error("Call information couldn't retrieve.")
          return nil
        end
      end
    end

    def getresponse
      responses = []
      while sock.has_read_data?(2)
        return nil if sock.eof?
        res = sock.get_once
        len = bytes_to_length(res[0, 4])
        firstbyte = 0
        print_debug("Initial length #{len}, resource length is #{res.length}") if datastore["DEBUG"] == true
        while firstbyte == 0 || (len != 0 && len + 8 < res.length)
          print_debug("Skinny length is #{len} and Data length is #{res.length}") if datastore["DEBUG"] == true
          r, m, lines = skinny_parser(res[firstbyte, len + 8])
          responses << [r, m, lines]
          if m =~ /\t/
            vprint_status("Response received: #{r}")
            m.split("\t").each do |k|
              vprint_status("  #{k}")
            end
          else
            if m.nil?
              vprint_status("Response received: #{r}")
            else
              vprint_status("Response received: #{r} => #{m}")
            end
          end
          firstbyte = firstbyte + len + 8
          print_debug("New first byte is #{firstbyte}") if datastore["DEBUG"] == true
          unless res[firstbyte, 4].nil? # or res[len,4].unpack('H*')[0] == "00000000"
            print_debug("Extra response received: #{res[firstbyte, 4]}, #{res[firstbyte, 4].unpack('H*')[0]}") if datastore["DEBUG"] == true
            len = bytes_to_length(res[firstbyte, 4])
            print_debug("First Byte: #{firstbyte}, Length #{len}") if datastore["DEBUG"] == true
          end
        end
        print_debug("Multi-response loop is broken.") if datastore["DEBUG"] == true
      end
      print_debug("No data to read.") if datastore["DEBUG"] == true
      return responses
    rescue => e
      return r = ["error", e.class, nil]
    end

    def getconfiguration(r, m, lines, configinfo)
      m.split("\t").each do |l|
        print_good("  #{l}") if configinfo
      end

      unless lines.nil?
        linestatrecevied = 0
        i = 0
        c = 0
        while linestatrecevied < lines
          # obtaining line data
          sock.put(prep_linestatreq(i + 1))
          vprint_status("Line request sent for #{i + 1} of #{lines}")

          print_debug("Line status is looping") if datastore["DEBUG"] == true
          responses = getresponse

          responses.each do|response|
            r, m, l = response
            if r == "LineStatMessage"
              print_good("The line #{i + 1} information:") if configinfo
              m.split("\t").each do |l|
                print_good("  #{l}") if configinfo
              end
              linestatrecevied += 1
              i += 1
              break
            end
          end

          c += 1 if responses == []
          if c == 3
            print_error("Line information couldn't retrieve.")
            return nil
          end
        end
      end
    end

    def prep_softkeyevent(e = "redial", l = 0, c = 0)
      events = { "redial" => "\x01", "newcall" => "\x02", "hold" => "\x03", "transfer" => "\x04",
              "callfwdall" => "\x05", "callfwdbusy" => "\x06", "callfwdnowanswer" => "\x06",
              "endcall" => "\x09", "resume" => "\x10", "answer" => "\x11", "info" => "\x12", "confrn" => "\x13",
              "park" => "\x14", "join" => "\x15", "meetme" => "\x16", "pickup" => "\x17", "gpickup" => "\x18",
              "rmlstc" => "\x19", "callback" => "\x20", "barge" => "\x21", "dnd" => "\x22", "acct" => "\x23",
              "flash" => "\x24", "login" => "\x25", "hlog" => "\x26", "conflist" => "\x27", "select" => "\x28",
              "trnsfvm" => "\x29", "cbarge" => "\x30", "livercd" => "\x31", "mobility" => "\x32"
      }
      p =  "\x26\x00\x00\x00"          # softkeyevent message
      p << "#{events[e]}\x00\x00\x00"  # event
      p << length_to_bytes(l, 4)        # line
      p << length_to_bytes(c, 4)        # call identifier
      b =  length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_register(device, device_ip, cipc = "ipphone")
      mac = device[3, 12]
      p = "\x01\x00\x00\x00" # register message
      p << "#{device}\x00\x00\x00\x00\x00\x00\x00\x00\x00" # device id
      p << ip_to_bytes(device_ip) # "\xC0\xA8\n6" #ip address
      if cipc == "cipc"
        # cisco ip communicator client
        device_type = 30016
      else
        # cisco ip phone
        device_type = 309
      end
      p << length_to_bytes(device_type, 4) # device type
      p << "\x05\x00\x00\x00"

      if cipc == "cipc"
        # cisco ip communicator client
        p << "\x00\x00\x00\x00\x14\x00\x72\x85\x01\x00\x00\x00\x00\x00\x00\x00#{mac_to_bytes(mac)}\x00\x00\x00\x00"
        p << "\x00\x00\x03\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        p << "\x00\x00\x00\x00\x00\x00\x00\x00CIPC-Default\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        p << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      else
        # cisco ip phone
        p << "\x00\x00\x00\x00\x06\x00\x00\x84\x01\x00\x00\x00\x00\x00\x00\x00"
      end

      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_unregister
      prep_raw("\x27")
    end

    def prep_49(l = 2, s = 1)
      p =  "\x49\x00\x00\x00" # buttontemplate message
      p << length_to_bytes(l, 4)       # line
      p << length_to_bytes(s, 4)       # state
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_openreceivechannelack(device_ip, port = 1234)
      p =  "\x22\x00\x00\x00" # openreceivechannelack message
      p << length_to_bytes(0, 4)       # orcOk
      p << ip_to_bytes(device_ip) # "\xC0\xA8\n6" #ip address
      p << length_to_bytes(port, 2).reverse # "\xAC\r" #port number
      p << length_to_bytes(333124, 4)       # orcOk
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_offhook(l = 0, c = 0)
      p =  "\x06\x00\x00\x00"         # offhook message
      p << length_to_bytes(l, 4)       # line
      p << length_to_bytes(c, 4)       # call identifier, source number
      b =  length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_onhook
      p =  "\x07\x00\x00\x00"         # onhook message
      p << length_to_bytes(0, 4)       # line
      p << length_to_bytes(0, 4)       # call identifier, source number
      b =  length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def skinny_parser(p)
      l = bytes_to_length(p[0, 3])
      r = p[8, 4].unpack('H*')[0]
      lines = nil

      print_debug("Response reference is #{r}") if datastore["DEBUG"] == true

      case r
      when "9d000000"
        r = "RegisterRejectMessage"
        m = p[12, l - 4]
      when "81000000"
        r = "RegisterAckMessage"
        m = "Registration successful."
      when "93000000"
        r = "ConfigStatMessage"
        devicename = p[12, 15]
        userid = bytes_to_length(p[27, 4])
        station = bytes_to_length(p[31, 4])
        username = p[35, 40]
        domain = p[75, 40]
        lines = bytes_to_length(p[116, 4])
        speeddials = bytes_to_length(p[120, 4])
        m = "Device: #{devicename}\tUser ID: #{userid}\tLines: #{lines}\tSpeed Dials: #{speeddials}\tDomain: #{domain}"
      when "9b000000"
        v = p[4, 1].unpack('H*')[0]
        r = "CapabilitiesReqMessage"
        m = "Version: #{v}"
      when "3f010000"
        # no details required at this point
        r = "UserToDeviceDataVersion1Message"
        m = nil
      when "42010000"
        # ConfigStatMessage for CM7 type C
        r = "ConfigStatMessage"
        devicename = p[12, 15]
        lines = bytes_to_length(p[36, 1])
        domain = p[43, 40]
        m = "Device: #{devicename}\tUser ID: \tLines: #{lines}\tSpeed Dials: \tDomain: #{domain}"
      when "97000000"
        r = "ButtonTemplateMessage"
        m = nil
      when "21010000"
        r = "ClearPriNotifyMessage"
        m = nil
      when "15010000"
        r = "ClearNotifyMessage"
        m = nil
      when "12010000"
        r = "DisplayPromptStatusMessage"
        m = nil
      when "82000000"
        r = "StartToneMessage"
        dialtone = bytes_to_length(p[16, 4])
        lineid = bytes_to_length(p[20, 4])
        callidentifier = bytes_to_length(p[24, 4])
        m = "Call Identifier: #{callidentifier}\tLine: #{lineid}"
      when "83000000"
        r = "StopToneMessage"
        m = nil
      when "9f000000"
        r = "Reset"
        m = nil
      when "16010000"
        r = "ActivateCallPlanMessage"
        m = nil
      when "10010000"
        r = "SelectSoftKeysMessage"
        m = nil
      when "09010000"
        r = "SoftKeySetResMessage"
        m = nil
      when "08010000"
        r = "SoftKeyTemplateResMessage"
        m = nil
      when "11010000"
        r = "CallStateMessage"
        m = nil
      when "86000000"
        r = "SetLampMessage"
        m = nil
      when "88000000"
        r = "SetSpeakerModeMessage"
        m = nil
      when "85000000"
        r = "SetRingerMessage"
        m = nil
      when "8f000000"
        r = "CallInfoMessage"
        m = nil
      when "4a010000"
        r = "CM5CallInfoMessage"
        m = nil
      when "00010000"
        r = "KeepAliveAckMessage"
        m = nil
      when "13010000"
        r = "ClearPromptStatusMessage"
        m = nil
      when "45010000"
        r = "UnknownReadyMessage145"
        m = nil
      when "92000000"
        r = "LineStatMessage"
        lineid = bytes_to_length(p[12, 4])
        dirnumber = p[16, 24]
        fqdisplayname = p[40, 40]
        m = "Line: #{lineid}\tDirectory Number: #{dirnumber}\tDisplay Name: #{fqdisplayname}"
      when "47010000"
        # LineStatMessage for CM7 type C
        r = "LineStatMessage"
        lineid = bytes_to_length(p[12, 4])
        # dirnumber = p[20,5]
        # fqdisplayname = p[25,5]
        dirnumber = p[20, 100].split("\x00")[0]
        fqdisplayname = p[20, 100].split("\x00")[1]
        m = "Line: #{lineid}\tDirectory Number: #{dirnumber}\tDisplay Name: #{fqdisplayname}"
      when "90000000ForwardStatMessage"
        r = "ForwardStatMessage"
        fstatus = bytes_to_length(p[12, 4])
        lineid = bytes_to_length(p[16, 4])
        if fstatus
          fmsg = ""
          fall = bytes_to_length(p[20, 4])
          fallnumber = p[24, 24]
          fmsg << "\tForward for all: #{fallnumber}" if fall

          fbusy = bytes_to_length(p[48, 4])
          fbusynumber = p[52, 24]
          fmsg << "\tForward on busy: #{fbusynumber}" if fbusy

          fnoanswer = bytes_to_length(p[76, 4])
          fnoanswernumber = p[80, 24]
          fmsg << "\tForward on no answer: #{fnoanswernumber}" if fnoanswer

          m = "Line #{lineid}: #{fmsg}"
        else
          m = "Line #{lineid}: Forward status couldn't parsed!"
        end
      when "90000000"
        r = "ForwardStatMessage"
        fstatus = bytes_to_length(p[12, 4])
        lineid = bytes_to_length(p[16, 4])

        fmsg = ""
        # fall = bytes_to_length(p[20,4])
        fallnumber = p[24, 24].split("\x00")[0]
        fmsg << "\t  Forward for all: #{fallnumber}"

        # fbusy = bytes_to_length(p[48,4])
        fbusynumber = p[52, 24].split("\x00")[0]
        fmsg << "\t  Forward on busy: #{fbusynumber}"

        # fnoanswer = bytes_to_length(p[76,4])
        fnoanswernumber = p[80, 24].split("\x00")[0]
        fmsg << "\t  Forward on no answer: #{fnoanswernumber}"

        m = "Line #{lineid}: #{fmsg}"
      else
        m = "#{r}"
        r = "Unknown Response"
      end
      [r, m, lines]
    end

    def prep_linestatreq(l = 1)
      p =  "\x0b\x00\x00\x00" # linestatreq message
      p << length_to_bytes(l, 4) # line
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_configstatreq
      prep_raw("\x0c")
    end

    def prep_raw(byte)
      p =  "#{byte}\x00\x00\x00" # raw message
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_alarm(device, software, _alarm = 20, severity = "i")
      p =  "\x20\x00\x00\x00" # alarm message
      if severity == "w"
        p << "\x01\x00\x00\x00" # warning
      else
        p << "\x02\x00\x00\x00" # informational
      end
      p << "31: Name=#{device} Load= 7.0(3.0S) File Auth Fail: #{software}" # message
      p << "\x00" * 13 # null
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_ipport(port = 44045)
      p =  "\x02\x00\x00\x00" # ipport message
      p << length_to_bytes(port, 2).reverse # "\xAC\r" #port number
      p << "\x00\x00"
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_buttontemplatereq
      prep_raw("\x0E")
    end

    def prep_softkeytemplatereq
      prep_raw("\x28")
    end

    def prep_softkeysetreq
      prep_raw("\x25")
    end

    def prep_capabilitiesres
      null = "\x00" * 11
      p =  "\x10\x00\x00\x00" # capabilities response
      p << "\x07\x00\x00\x00" # capabilities count
      p << "\x19\x00\x00\x00(#{null}\x04\x00\x00\x00(#{null}"
      p << "\x02\x00\x00\x00(#{null}\x0F\x00\x00\x00Z#{null}"
      p << "\x10\x00\x00\x00Z#{null}\v\x00\x00\x00Z#{null}\f\x00\x00\x00Z#{null}"
      b = length_to_bytes(p.length, 4) # length
      b + "\x14\x00\x00\x00" + p
    end

    def prep_forwardstatreq(l = 1)
      p =  "\x09\x00\x00\x00" # linestatreq message
      p << length_to_bytes(l, 4) # line
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_registeravailablelines(l = 4)
      p =  "\x2d\x00\x00\x00" # linestatreq message
      p << length_to_bytes(l, 4) # line
      b = length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def prep_timedatereq
      prep_raw("\x0d")
    end

    def prep_keepalive
      prep_raw("\x00")
    end

    def prep_keypadbutton(b, l = 0, c = 0)
      p =  "\x03\x00\x00\x00"         # softkeyevent message
      p << length_to_bytes(b, 4)       # number
      p << length_to_bytes(l, 4)       # line
      p << length_to_bytes(c, 4)       # call identifier, source number
      b =  length_to_bytes(p.length, 4) # length
      b + "\x00\x00\x00\x00" + p
    end

    def bytes_to_length(b)
      l = b.reverse.unpack('H*')[0].to_i(16)
      l
    end

    def length_to_bytes(l, n = 2)
      l = "%0#{n * 2}X" % l
      b = [l].pack('H*').reverse
      b
    end

    def ip_to_bytes(dip)
      # print_status("Device IP: #{dip}")
      b = []
      dip.split('.').each do|p|
        b << [ "%02X" % p ].pack('H*')
      end
      b = b.join('')
      b
    end

    def mac_to_bytes(mac)
      [mac].pack('H*')
    end

    def macfileimport(f)
      print_good("MAC File is " + f.to_s + "\n")
      macs = []
      contents = IO.read(f)
      contents.split("\n").each do |line|
        macs << format_mac(line).upcase
      end
      macs
    end
  end
end
