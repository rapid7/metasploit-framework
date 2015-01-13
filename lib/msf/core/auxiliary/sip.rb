##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'rex/socket'
require 'timeout'

module Msf

module Auxiliary::SIP
  attr_accessor :listen_addr, :listen_port, :context, :logfile, :customheaders
  attr_accessor :sock, :thread, :dest_addr, :dest_port, :proto, :vendor, :macaddress
  attr_accessor :prxclient_port, :prxclient_ip, :client_port, :client_ip
  attr_accessor :prxserver_port, :prxserver_ip, :server_port, :server_ip

  include Msf::Auxiliary::Report

  #
  # Start the SIP Socket
  #
  def sipsocket_start(sockinfo)
    raise ::Rex::ArgumentError, 'Destination IP address required' if sockinfo["dest_addr"] == nil
    raise ::Rex::ArgumentError, 'Protocol is required' if sockinfo["proto"] == nil
    self.listen_port = sockinfo["listen_port"].to_i || 5060
    self.dest_addr = sockinfo["dest_addr"]
    self.dest_port = sockinfo["dest_port"].to_i || 5060
    self.proto = sockinfo["proto"].downcase
    if vendor
      self.vendor = sockinfo["vendor"].downcase
    else
      'generic'
    end
    self.macaddress = sockinfo["macaddress"] || '000000000000'

    if sockinfo["listen_addr"]
      self.listen_addr = sockinfo["listen_addr"]
    else
      self.listen_addr = Rex::Socket.source_address(self.dest_addr)
    end
  end

  #
  # Connect the SIP Socket
  #
  def sipsocket_connect
    case self.proto
      when 'udp'
        listen_port = self.listen_port
        while listen_port
          begin
            self.sock = Rex::Socket::Udp.create(
                'LocalHost' => listen_addr,
                'LocalPort' => listen_port,
                'Context'   => context
            )
            self.listen_port = listen_port
            print_debug("UDP listener initiated on #{listen_port}") if datastore["DEBUG"] == true and self.sock
            break
          rescue ::Rex::AddressInUse
            listen_port += 1
          end
        end
      when 'tcp'
        listen_port = datastore["CPORT"].to_i || 5060
        while listen_port
          begin
            self.sock = Rex::Socket::Tcp.create(
                'PeerHost'      => dest_addr,
                'PeerPort'      => dest_port,
                'LocalPort'     => listen_port,
                'Context'       => context,
            )
            self.listen_port = listen_port
            print_debug("TCP socket connected for #{dest_addr}, local port is #{listen_port}") if datastore["DEBUG"] == true and self.sock
            break
          rescue ::Rex::AddressInUse
            listen_port += 1
          end
        end
      when 'tls'
        listen_port = datastore["CPORT"].to_i || 5060
        while
          begin
            self.sock = Rex::Socket::Tcp.create(
                'PeerHost'      => dest_addr,
                'PeerPort'      => dest_port,
                'LocalPort'     => listen_port,
                'SSL'           => true,
                'SSLVerifyMode' => 'NONE',
                'Context'       => context,
            )
            self.listen_port = listen_port
            print_debug("TLS socket connected for #{dest_addr}, local port is #{listen_port}") if datastore["DEBUG"] == true  and self.sock
            break
          rescue ::Rex::AddressInUse
            listen_port += 1
          end
        end
      else
        raise ::Rex::ArgumentError, 'Protocol is invalid. Valid protocols are UDP, TCP or TLS.'
    end
  end

  # Stop the SIPSocket
  def sipsocket_stop
    self.sock.close if self.sock and (! self.sock.closed?)
    self.thread.kill if self.thread
  end

  #
  # Print results
  #
  def printresults(results,context={})

    return if results.nil? or results["rdata"].nil?
    status = results["status"]
    rdata = results["rdata"]
    rdebug = results["rdebug"]
    rawdata = results["rawdata"]
    method = context["method"]
    user = context["user"]
    password = context["password"]

    report =  "#{rdata['source']}\n\tResponse\t: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}\n"
    report << "\tServer \t\t: #{rdata['server']}\n" if rdata['server']
    report << "\tWarning \t: #{rdata['warning']}\n" if rdata['warning']
    report << "\tUser-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
    report << "\tRealm \t\t: #{rdata['digest']['realm']}\n" if rdata['digest']

    printdebug(results) if datastore["DEBUG"] == true

    if status =~ /received|succeed/
      #reporting the service
      if rdata['server']
        service=rdata['server'].to_s
      elsif rdata['agent']
        service=rdata['agent'].to_s
      else
        service='SIP Server'
      end

      # reporting the service information
      report_service(
          :host	  => self.dest_addr,
          :port	  => self.dest_port,
          :sname	=> 'sip',
          :proto  => proto.downcase,
          :info   => service
      )

      # reporting the validated credentials
      res = report_creds(user,password,status) if user != nil
      report << res if ! res.nil?
      print_good(report)
    else
      report << "\tCredentials\t: User => #{user} Password => #{password}\n" if user != nil and datastore['LOGIN']
      if method == 'register'
        print_status(report)
      else
        vprint_status(report)
      end
    end
  end

  # reporting the validated credentials
  def report_creds(user,password,status)
    if status =~ /without/
      user="User=NULL,FROM=#{datastore["FROM"]},TO=#{datastore["TO"]}"
      password=nil
      res = nil
    else
      if status =~ /succeed/
        res = "\tCredentials\t: User => #{user} Password => #{password}"
      else
        res = nil
      end
    end

    report_auth_info(
        :host   => self.dest_addr,
        :port   => self.dest_port,
        :sname  => 'sip',
        :user   => user,
        :pass   => password,
    )
    return res
  end
  # Print debug output
  def printdebug(results)
    rdebug = results['rdebug']
    rawdata = results['rawdata']
    if rawdata != nil
    print_debug("Raw Response for #{self.dest_addr}:\n\t#{rawdata.split("\n").join("\n\t")}")
    rdebug.each { |r| print_debug("Irrelevant Response for #{self.dest_addr}:  #{r['resp']} #{r['resp_msg']}") }
    end

    if self.customheaders and self.customheaders != ""
      print_debug("Custom Headers:")
      print_debug("\t#{self.customheaders.gsub("\r\n","")}")
    end
  end

  # Convert Errors to Message
  def convert_error(err)
    case err
      when :cred_required
        return "Credentials Required"
      when :no_response
        return "No Response"
      when :succeed_withoutlogin
        return "Request Succeed without Login Information"
      when :ringing
        return "Ringing"
      when :user_busy
        return "User is Busy"
      when :succeed
        return "Request Succeed"
      when :not_found
        return "Not Found"
      when :failed
        return "Authentication Failed"
      when :send_error
        return "Request Sending is Failed"
      when :server_error
        return "Internal Server Error"
      when :nodigest
        return "No Digest Found in 'Unauthorized' Response"
      when :authorization_error
        return "Authorization Error"
      when :decline_error
        return "Server Declined"
      when :protocol_error
        return "Protocol Error"
      else
        return "Unknown Error #{err}"
    end
  end

  #
  # Send Register
  #
  def send_register(req_options={})
    login = req_options["login"] || false
    results=generic_request("REGISTER",req_options)
    if results["status"] == :received and results["rdata"] != nil
      case results["rdata"]["resp"]
        when "200"
          results["status"]=:succeed_withoutlogin
        when /^40/
          if login
            req_options['to'] = req_options['from']
            if self.vendor == "mslync"
              results=auth("REGISTER",req_options,results,true)
              if status == :cred_required or status == :failed
                results=auth("REGISTER",req_options,results)
              end
            else
              results=auth("REGISTER",req_options,results)
            end
          else
            results["status"]=:cred_required
          end
        when /^60/
          results["status"]=:decline_error
        else
          results["status"]=:protocol_error
      end
    end
    return results
  end

  #
  # Send Options
  #
  def send_options(req_options={})
    return generic_request("OPTIONS",req_options)
  end

  #
  # Send Negotiate
  #
  def send_negotiate(req_options={})
    return generic_request("NEGOTIATE",req_options)
  end

  #
  # Send Notify
  #
  def send_notify(req_options={})
    return generic_request("NOTIFY",req_options)
  end
  #

  #
  # Send ACK
  #
  def send_ack(req_options={})
    return generic_request("ACK",req_options,no_response=true)
  end

  # Send Subscribe
  #
  def send_subscribe(req_options={})
    return generic_request_withauth("SUBSCRIBE",req_options)
  end

  #
  # Send Message
  #
  def send_message(req_options={})
    generic_request_withauth("MESSAGE",req_options)
  end


  #
  # Send Invite
  #
  def send_invite(req_options={})
    generic_request_withauth("INVITE",req_options)
  end


  #
  # Send generic request with authentication
  #
  def generic_request_withauth(method,req_options={})
    login = req_options["login"] || false
    loginmethod = req_options["loginmethod"] || method

    if login and loginmethod == "REGISTER"
      regopts=req_options.clone

      #Cisco generic Register methods requests same FROM and TO fields
      if self.vendor == "ciscogeneric"
        regopts['to']=regopts['from']
      else
        #From and TO fields should be Username for REGISTER
        if datastore['USEREQFROM'] == true
          regopts['from']=regopts['user']
          regopts['to']=regopts['user']
        end
      end

      results = send_register(regopts)
      reg_status = results["status"]

      printdebug(results) if datastore["DEBUG"] == true

      req_options['callopts']=callopts if callopts != nil

      # Cleaning Old Session Data
      req_options['nonce'] = nil
      if req_options['callopts'] != nil
        req_options['callopts'].delete('seq')
        req_options['callopts'].delete('callid')
        req_options['callopts'].delete('tag')
      end
    end

    print_debug("No authentication performed.") if datastore['DEBUG']

    if method == "MESSAGE" and datastore["DOS_COUNT"]
      datastore["DOS_COUNT"].times {
        results=generic_request(method,req_options)
      }
      print_debug("Request packet sent.") if datastore['DEBUG']
    else
      results=generic_request(method,req_options)
      print_debug("Request packet sent.") if datastore['DEBUG']
    end

    if results["rawdata"].nil?
      print_error("No response recieved!")
      return
    else
      printdebug(results) if datastore["DEBUG"] == true
    end

    if results["status"] == :received and results["rdata"] != nil
      results["status"] = parse_rescode(results["rdata"])
      case results["status"]
        when :cred_required
          if login
            ack_options=req_options.clone
            ack_options['callopts']=results["callopts"].clone
            ack_options['callopts'].delete('seq')
            send_ack(ack_options) if method == "INVITE"

            results=auth(method,req_options,results)

            printdebug(results) if datastore["DEBUG"] == true

            if :received and results["rdata"] != nil
              results["status"] = parse_rescode(results["rdata"])
            else
              results["rdata"] = nil
              results["status"] = :protocol_error
            end
          end
        when :succeed
          results["status"] = :succeed_withoutlogin if reg_status != :succeed and results["status"] == :succeed
        else
          results["status"] = :protocol_error
      end
    end

    results["callopts"] = req_options["callopts"]
    return results
  end






  #
  # Send Raw Data
  #
  def send_rawdata(rawdata)
    begin
      self.sock.sendto(rawdata, dest_addr, dest_port, 0)
      send_state=:success
    rescue ::Interrupt
      send_state=:error
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
      send_state=:error
      nil
    end
    return send_state
  end

  #
  # Parse Result Code
  #
  def parse_rescode(rdata)
    case rdata['resp']
      when "200"
        result=:succeed
      when "180"
        result=:ringing
      when "100"
        result=:trying
      when /^404/
        result=:not_found
      when /^40/
        result=:cred_required
      when "486"
        result=:user_busy
      when /^60/
        result=:decline_error
      when /^50/
        result=:server_error
      else
        result=:protocol_error
    end
  end

  #
  # Send Generic SIP Request
  #
  def generic_request(method,req_options={},no_response=false)
    callopts,status=send_data(method,req_options)
    return nil if no_response

    results={}

    if status == :error
      results['status'] = :send_error
    else
      results=resp_get(method)
      if  results['rdata'] == nil
        results['status'] = :no_response
      else
        results["callopts"] = callopts
        results['status'] = :received
      end
    end

    return results
  end


  #
  # Authentication
  #
  def auth(method,req_options,results)
    initmslync = results["initmslync"] || false

    case
      when initmslync
        req_options['ntlm']=results["rdata"]['ntlm']
        req_options['initmslync']=true
      when results["rdata"]['digest']
        req_options['digest']=results["rdata"]['digest']
      when results["rdata"]["ntlm"]
        req_options['ntlm']=results["rdata"]['ntlm']
      else
        return results
    end

    req_options['callopts'] = results["callopts"] if results["callopts"] != nil

    #Cisco generic Register methods requests same FROM and TO fields
    req_options['to'] = req_options['from'] if self.vendor == "ciscogeneric"

    #Sending Request with Nonce or NTLM request
    results["callopts"],send_state=send_data(method,req_options)
    if send_state == :error
      results["status"] = :send_error
      return results
    end

    #Receiving Authentication Response
    results=resp_get(method,results["rdebug"])
    if results["rdata"] == nil
      results["status"] = :no_response
      return results
    end

    case results["rdata"]["resp"]
      when "200"
        results["status"] = :succeed
      when "/^48/"
        results["status"] = :succeed
      when "/^18/"
        results["status"] = :succeed
      when /^40/
        results["status"] = :failed
      else
        results["status"] = :authorization_error
    end
    return results
  end

  #
  # Receive Data
  #
  def recv_data
    begin
      case self.proto
        when 'udp'
          r = self.sock.recvfrom(65535, 3)
        when 'tcp'
          r = self.sock.get_once(-1, 5)
        when 'tls'
          r = self.sock.get_once(-1, 5)
      end
    rescue
      r = nil
    end

    if r.nil?
      rdata,rawdata=nil,nil
    else
      rdata,rawdata=parse_reply(r)
    end
    return rdata,rawdata
  end

  #
  # Response Check
  #
  def resp_get(method,rdebug=[])
    possible= /^18|^20|^40|^48|^60|^50/
    rdata,rawdata=recv_data
    rdebug << rdata

    while (rdata != nil and !(rdata['resp'] =~ possible))
      rdata,rawdata=recv_data
      break if rdebug.length > 9
    end

    results = {
        "rdata" => rdata,
        "rdebug" => rdebug,
        "rawdata" => rawdata
    }

    return results
  end

  #
  # Nonce Calculation
  #
  def auth_calc(digestopts)
    cnonce=Rex::Text.rand_text_alphanumeric(10)
    nc="00000001"

    if digestopts['algorithm'] == 'MD5-sess'
      h1 = Digest::MD5.hexdigest("#{digestopts['username']}:#{digestopts['realm']}:#{digestopts['password']}")
      hash1 = Digest::MD5.hexdigest("#{h1}:#{digestopts['nonce']}:#{cnonce}")
    else
      hash1 = Digest::MD5.hexdigest("#{digestopts['username']}:#{digestopts['realm']}:#{digestopts['password']}")
    end

    hash2 = Digest::MD5.hexdigest("#{digestopts['req_type']}:#{digestopts['uri']}")

    if digestopts['qop'] =~ /auth/
      response=Digest::MD5.hexdigest("#{hash1}:#{digestopts['nonce']}:#{nc}:#{cnonce}:#{digestopts['qop']}:#{hash2}")
    else
      response=Digest::MD5.hexdigest("#{hash1}:#{digestopts['nonce']}:#{hash2}")
    end

    authdata = "username=\"#{digestopts['username']}\", realm=\"#{digestopts['realm']}\", nonce=\"#{digestopts['nonce']}\", uri=\"#{digestopts['uri']}\", response=\"#{response}\""
    if digestopts['algorithm']
      authdata << ", algorithm=#{digestopts['algorithm']}"
    else
      authdata << ", algorithm=MD5"
    end
    authdata << ", cnonce=\"#{cnonce}\"" if digestopts['algorithm'] == "MD5-sess" or digestopts['qop'] =~ /auth/
    authdata << ", qop=#{digestopts['qop']}, nc=#{nc}" if digestopts['qop'] =~ /auth/

    return authdata
  end


  #
  # Send Data
  #
  def send_data(req_type,req_options)
    data,callopts = create_req(req_type,req_options)
    if datastore["DEBUG"] == true
      print_debug("Raw Request for #{dest_addr}:\n\t#{data.split("\n").join("\n\t")}")
    end

    begin
      case self.proto
        when 'udp'
          self.sock.sendto(data, dest_addr, dest_port, 0)
          send_state=:success
        when 'tcp'
          self.sock.put(data)
          send_state=:success
        when 'tls'
          self.sock.put(data)
          send_state=:success
      end
    rescue ::Interrupt
      send_state=:error
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
      send_state=:error
      nil
    end
    return callopts,send_state
  end

  #
  # EPID Calculation for Microsoft Lync
  #
  def epidcalc
    epid="5e4b3e004d" #Rex::Text.rand_text_alphanumeric(20)
    hash=Digest::SHA1.hexdigest "\x03\xfb\xac\xfc\x73\x8a\xef\x46\x91\xb1\xe5\xeb\xee\xab\xa4\xfe#{epid}"
    #puts hash
    h=[]
    20.times{|i|
      h << hash[i*2,2]
    }
    sipinstance = "#{h[0,4].reverse.join}-#{h[4,2].reverse.join}-#{h[6,2].reverse.join}-#{h[8,2].reverse.join}-#{h[10,6].join}"

    #fixed epid and sipinstance
    epid,sipinstance="5e4b3e004d","3F1E42D5-E5F4-5A6E-97AF-BA4AC0D40D4B"
    return epid,sipinstance
  end


  #
  # Create the Request
  #
  def create_req(req_type,req_options)
    realm=req_options['digest_realm'] || req_options['realm'] || dest_addr
    user=req_options['user']
    from=req_options['from']  || user
    fromname=req_options['fromname']  || nil
    to=req_options['to'] || user
    password=req_options['password'] || nil
    callopts=req_options['callopts'] || {}
    seq=callopts['seq'].to_i+1 || 1
    callid=callopts['callid'] || "call#{Rex::Text.rand_text_alphanumeric(30)}"
    tag= callopts['tag'] || "#{Rex::Text.rand_text_alphanumeric(10)}"
    if vendor == "mslync"
      epid,sipinstance=epidcalc
    else
      epid,sipinstance=Rex::Text.rand_text_alphanumeric(10),"3F1E42D5-E5F4-5A6E-97AF-BA4AC0D40D4B"
    end

    branch=callopts['branch'] || "branch#{Rex::Text.rand_text_alphanumeric(10)}"
    msopaque=callopts['msopaque'] || "#{Rex::Text.rand_text_alphanumeric(12)}"

    case req_type
      when 'SUBSCRIBE'
        uri="sip:#{to}@#{realm}"
      when 'INVITE'
        uri="sip:#{to}@#{realm}"
      when 'MESSAGE'
        uri="sip:#{to}@#{realm}"
      when 'OPTIONS'
        #uri="sip:#{to}@#{realm}"
        uri="sip:#{realm}"
      when 'NEGOTIATE'
        uri="sip:#{dest_addr}:#{dest_port}"
      else
        uri="sip:#{realm}"
    end

    branchstr=";rport;branch=#{branch}" if self.vendor != "mslync" #if req_type != "NEGOTIATE"

    data = "#{req_type} #{uri} SIP/2.0\r\n"
    data << "Via: SIP/2.0/#{self.proto.upcase} #{self.listen_addr}:#{self.listen_port}#{branchstr}\r\n"
    if req_type == "NEGOTIATE"
      data << "Max-Forwards: 0\r\n"
    else
      data << "Max-Forwards: 70\r\n"
    end

    if req_type == "NEGOTIATE"
      data << "From: <sip:#{self.listen_addr}:#{self.listen_port}>;tag=#{tag}\r\n"
      data << "To: <sip:#{dest_addr}:#{dest_port}>\r\n"
    else
      if from =~ /@/
        data << "From: <sip:#{from}>;tag=#{tag};epid=#{epid}\r\n"
      elsif fromname != nil
        data << "From: \"#{fromname}\" <sip:#{from}@#{realm}>;tag=#{tag};epid=#{epid}\r\n"
      else
        data << "From: <sip:#{from}@#{realm}>;tag=#{tag};epid=#{epid}\r\n"
      end
      data << "To: <sip:#{to}@#{realm}>\r\n"
    end

    if self.vendor == 'mslync' or req_type == "OPTIONS"
      data << "Call-ID: #{callid}\r\n"
    else
      data << "Call-ID: #{callid}@#{self.listen_addr}\r\n"
    end

    if req_type == "OPTIONS"
      data << "CSeq: 1234 #{req_type}\r\n"
    else
      data << "CSeq: #{seq} #{req_type}\r\n"
    end


    case self.vendor
      when 'ciscodevice'
        contact_ext = "; +sip.instance=\"<urn:uuid:00000000-0000-0000-0000-#{self.macaddress}>\";+u.sip!devicename.ccm.cisco.com=\"SEP#{self.macaddress.upcase}\";+u.sip!model.ccm.cisco.com=\"#{datastore['CISCODEVICE']}\""
        uagent = datastore["USERAGENT"] || "Cisco IP Phone 7945"
        msq =""
      when 'mslync'
        contact_ext =";methods=\"INVITE, MESSAGE, INFO, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY\";proxy=replace"
        uagent = datastore["USERAGENT"] || "UCCAPI/15.0.4420.1017 OC/15.0.4420.1017 (Microsoft Lync)"
        msq = ";ms-opaque=#{msopaque}"
      else
        contact_ext = ''
        uagent = datastore["USERAGENT"] || "Viproy Penetration Testing Kit - Test Agent"
        msq =""
    end

    if req_type != "NEGOTIATE"

      if self.vendor == 'mslync'
        data << "Contact: <sip:#{self.listen_addr}:#{self.listen_port};transport=#{self.proto.downcase}#{msq}>#{contact_ext};+sip.instance=\"<urn:uuid:#{sipinstance}>\"\r\n"
      else
        if from =~ /@/
          data << "Contact: <sip:#{from}#{msq}> #{contact_ext}\r\n"
        else
          data << "Contact: <sip:#{from}@#{self.listen_addr}:#{self.listen_port}>#{contact_ext}\r\n"
        end
      end

      data << "User-Agent: #{uagent}\r\n"

      if self.vendor != 'mslync'
        data << "Supported: 100rel,replaces\r\n" if req_type != "OPTIONS"
        data << "Allow: PRACK, INVITE ,ACK, BYE, CANCEL, UPDATE, SUBSCRIBE,NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
        data << "Expires: 3600\r\n"
      end
    end

    #getting custom headers
    self.customheaders=getcustomheaders
    data << self.customheaders


    if self.vendor == 'mslync' and req_type != "NEGOTIATE"
      data << "Supported: gruu-10, adhoclist, msrtc-event-categories\r\n"
      data << "Supported: ms-forking\r\n"
      data << "Supported: ms-cluster-failover\r\n"
      data << "Supported: ms-userservices-state-notification\r\n"
      data << "ms-keep-alive: UAC;hop-hop=yes\r\n"
      #data << "ms-subnet: #{self.listen_addr.split(".")[0,3].join(".")}.0\r\n"

      case req_type
        when 'REGISTER'
          data << "Event: registration\r\n"
        when 'INVITE'
          data << "Event: invitation\r\n"
      end
    end
    if req_options['headers']
      req_options['headers'].split("|||").each { |h|
        data << "#{h}\r\n"
      }
    end

    if req_type == 'SUBSCRIBE'
      if req_options['subscribetype'] == "presence"
        data << "Event: presence\r\n"
        data << "Accept: application/pidf+xml, application/xpidf+xml\r\n"
      else
        data << "Event: message-summary\r\n"
        data << "Accept: application/simple-message-summary\r\n"
      end
    else
      data << "Accept: application/sdp\r\n"
    end

    data << "Compression: LZ77-8K\r\n" if req_type == "NEGOTIATE"

    case
      when req_options['initmslync']
        data << "Authorization: NTLM qop=\"auth\", realm=\"#{req_options['ntlm']['realm']}\", targetname=\"#{req_options['ntlm']['targetname']}\", gssapi-data=\"\", version=#{req_options['ntlm']['version']}\r\n"
      when req_options['digest']
        req_options['digest']['username']=user
        req_options['digest']['password']=password
        req_options['digest']['uri']=uri
        req_options['digest']['req_type']=req_type
        authdata=auth_calc(req_options['digest'])
        data << "Proxy-" if self.vendor == "mslync" or req_options['digest']["authtype"] == "proxy"
        data << "Authorization: Digest #{authdata}\r\n"
      when req_options['ntlm']
        req_options['ntlm']['username']=user
        req_options['ntlm']['password']=password
        req_options['ntlm']['uri']=uri
        req_options['ntlm']['req_type']=req_type
        authdata=auth_calc(req_options['ntlm'])
        data << "Proxy-" if self.vendor == "mslync" or req_options['ntlm']["authtype"] == "proxy"
        data << "Authorization: NTLM #{authdata}\r\n"
    end

    case req_type
      when 'INVITE'
        sdp_ID=Rex::Text.rand_text_numeric(9)
        s="Source"

        idata = "v=0\r\n"
        idata << "o=Cisco-SIPUA #{sdp_ID} #{sdp_ID} IN IP4 #{self.listen_addr}\r\n"
        idata << "s=#{s}\r\n"
        idata << "t=0 0\r\n"
        idata << "m=audio 16392 RTP/AVP 0 8 18 102 9 116 101\r\n"
        idata << "c=IN IP4 #{self.listen_addr}\r\n"
        idata << "a=rtpmap:3 GSM/8000"
        idata << "a=rtpmap:0 PCMU/8000\r\n"
        idata << "a=rtpmap:8 PCMA/8000\r\n"
        idata << "a=rtpmap:18 G729/8000\r\n"
        idata << "a=fmtp:18 annexb=no\r\n"
        idata << "a=rtpmap:102 L16/16000\r\n"
        idata << "a=rtpmap:9 G722/8000\r\n"
        idata << "a=rtpmap:116 iLBC/8000\r\n"
        idata << "a=fmtp:116 mode=20\r\n"
        idata << "a=rtpmap:101 telephone-event/8000\r\n"
        idata << "a=fmtp:101 0-15\r\n"
        idata << "a=sendrecv\r\n"
        idata << "\r\n"

        data << "Content-Type: application/sdp\r\n"
        data << "Content-Length: #{idata.length}\r\n\r\n"
        data << idata
      when 'MESSAGE'
        idata=req_options['message'] || ""
        messagetype=req_options['messagetype'] || "text/plain"
        data << "Content-Type: #{messagetype}\r\n"
        data << "Content-Length: #{idata.length}\r\n\r\n"
        data << idata
      else
        data << "Content-Length: 0\r\n\r\n"
    end

    callopts={ "callid" => callid, "seq" =>seq, "tag" => tag, "branch" => branch }
    return data,callopts
  end


  #Custom Headers
  def getcustomheaders
    #Building Custom Headers
    customheader = ""
    if datastore['CUSTOMHEADER'] != nil
      if (datastore['CUSTOMHEADER'] =~ /FUZZ\s+(.*)$/i)
        count=$1.split("|")[0].to_i
        fuzz=Rex::Text.pattern_create(count)
        customheader << datastore['CUSTOMHEADER'].gsub("|FUZZ #{count}|",fuzz)+"\r\n"
      else
        customheader << datastore['CUSTOMHEADER']+"\r\n"
      end
    end

    if datastore['P-Asserted-Identity'] != nil
      pid=datastore['P-Asserted-Identity']

      if (pid =~ /FUZZ\s*+(.*)$/i)
        count=$1.split("|")[0]
        fuzz=fromname=Rex::Text.pattern_create(count)
        pid=pid.gsub!("FUZZ #{count}",fuzz)
      end

      pid = pid+"@"+self.dest_addr if ! (pid =~ /@/)

      customheader << "P-Asserted-Identity: <sip:#{pid}>;party=called;screen=no;privacy=off\r\n"
    end

    if datastore['Remote-Party-ID'] != nil
      pid=datastore['Remote-Party-ID']

      if (pid =~ /FUZZ\s*+(.*)$/i)
        count=$1.split("|")[0]
        print_status("Count: #{count}")
        fuzz=fromname=Rex::Text.pattern_create(count.to_i)
        pid=pid.gsub!("FUZZ #{count}",fuzz)
      end

      pid = pid+"@"+self.dest_addr if ! (pid =~ /@/)

      customheader << "Remote-Party-ID: <sip:#{pid}>;party=called;screen=no;privacy=off\r\n"
    end


    customheader << "P-Charging-Vector: "+datastore['P-Charging-Vector']+"\r\n" if datastore['P-Charging-Vector'] != nil
    customheader << "Record-Route: "+datastore['Record-Route']+"\r\n" if datastore['Record-Route'] != nil
    customheader << "Route: "+datastore['Route']+"\r\n" if datastore['Route'] != nil

    return customheader
  end


  # Parse the authentication
  def parse_auth(data)
    result={}
    str=""
    var = nil
    quote = 0
    data.each_char { |c|
      quote += 1 if c == '"'
      if c == "="
        var = str
        val = nil
        str = ""
      else
        case quote
          when 0
            if c != ","
              str << c
            else
              result[var]=str
              var = nil
              str = ""
            end
          when 1
            str << c if c != '"'
          when 2
            quote = 0
        end
      end
    }
    return result
  end


  #
  # Parse Response
  #

  def parse_reply(pkt)
    rdata={}
    case self.proto
      when 'udp'
        return if not pkt[1]
        rawdata=pkt[0]
        rdata["source"] = "#{pkt[1]}:#{pkt[2]}"
      when 'tcp'
        rawdata=pkt
        rdata["source"] = "#{dest_addr}:#{dest_port}"
      when 'tls'
        rawdata=pkt
        rdata["source"] = "#{dest_addr}:#{dest_port}"
    end

    rdata["resp"] = rawdata.split(/\s+/)[1]
    rdata["resp_msg"] = rawdata.split("\r")[0]


    if(rawdata =~ /^User-Agent:\s*(.*)$/i)
      rdata["agent"] = "#{$1.strip}"
    end

    if(rawdata =~ /^Allow:\s+(.*)$/i)
      rdata["verbs"] = "#{$1.strip}"
    end

    if(rawdata =~ /^Server:\s+(.*)$/)
      rdata["server"] = "#{$1.strip}"
    end
    if(rawdata =~ /^Warning:\s+(.*)$/)
      rdata["warning"] = "#{$1.strip}"
    end

    if(rawdata =~ /^Proxy-Require:\s+(.*)$/)
      rdata["proxy"] = "#{$1.strip}"
    end

    if(rawdata =~ /^WWW-Authenticate:\s*(.*)$/i)
      header=$1
      t=header.split(" ")[0]
      type=t.downcase
      data="#{header.strip.gsub("#{t} ","")}"
      rdata[type] = parse_auth(data)
      rdata[type]["authtype"]="www"
    end
    if(rawdata =~ /^Proxy-Authenticate:\s*(.*)$/i)
      header=$1
      t=header.split(" ")[0]
      type=t.downcase
      data="#{header.strip.gsub("#{t} ","")}"
      rdata[type] = parse_auth(data)
      rdata[type]["authtype"]="proxy"
    end
    if(rawdata =~ /^From:\s+(.*)$/)
      rdata["from"] = "#{$1.strip.split(";")[0].gsub("<sip:","").gsub(">","")}"
    end
    if(rawdata =~ /^To:\s+(.*)$/)
      rdata["to"] = "#{$1.strip.split(";")[0].gsub("<sip:","").gsub(">","")}"
    end
    if(rawdata =~ /^Contact:\s+(.*)$/)
      rdata["contact"] = "#{$1.strip.gsub(/[<|>]/,"")}"
    end
    return rdata,rawdata
  end

end

end
