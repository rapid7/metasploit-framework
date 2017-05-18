##
# $Id: smb_enumshares.rb 8813 2010-03-14 03:44:50Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SMB Share Enumeration',
      'Version'     => '$Revision$',
      'Description' => 'Determine what shares are provided by the SMB service and which ones are readable/writable',
      'Author'      => 
        [
          'hdm',
          'nebulus'
        ],

      'License'     => MSF_LICENSE,
      'DefaultOptions' => {
        'DCERPC::fake_bind_multi' => false
      }
    )
    register_options(
        [
          OptBool.new('VERBOSE', [ false, 'Show discovered files', false])
        ], self.class)

    deregister_options('RPORT', 'RHOST')
  end

  def share_type(val)
    [
      'DISK',
      'PRINTER',
      'DEVICE',
      'IPC',
      'SPECIAL',
      'TEMPORARY'
    ][val]
  end

  def device_type_int_to_text(device_type)
    types = ["UNSET", "BEEP", "CDROM", "CDROM FILE SYSTEM", "CONTROLLER", "DATALINK",
      "DFS", "DISK", "DISK FILE SYSTEM", "FILE SYSTEM", "INPORT PORT", "KEYBOARD",
      "MAILSLOT", "MIDI IN", "MIDI OUT", "MOUSE", "UNC PROVIDER", "NAMED PIPE",
      "NETWORK", "NETWORK BROWSER", "NETWORK FILE SYSTEM", "NULL", "PARALLEL PORT",
      "PHYSICAL NETCARD", "PRINTER", "SCANNER", "SERIAL MOUSE PORT", "SERIAL PORT",
      "SCREEN", "SOUND", "STREAMS", "TAPE", "TAPE FILE SYSTEM", "TRANSPORT", "UNKNOWN",
      "VIDEO", "VIRTUAL DISK", "WAVE IN", "WAVE OUT", "8042 PORT", "NETWORK REDIRECTOR",
      "BATTERY", "BUS EXTENDER", "MODEM", "VDM"]
    return types[device_type]
  end

  def eval_host(ip, share)
    read = write = false
    return false,false,nil,nil if share == 'IPC$'

    simple.connect("\\\\#{ip}\\#{share}")

    begin
      device_type = self.simple.client.queryfs_fs_device['device_type']

      if(not device_type)
        print_error("\\\\#{ip}\\#{share}: Error querying filesystem device type")
        return false,false,nil,nil
      end
      rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
        if(e.to_s =~ /The server responded with error: 0xffff0002/)
        # 0xffff0002 means that the server can't handle the request for device type
          device_type=-1
        elsif(	e.to_s =~ /The server responded with error: STATUS_INVALID_DEVICE_REQUEST/)
          return false,false,"Invalid device request"
        elsif(	e.to_s =~ /The server responded with error: 0x00040002/ )
          return false,false,"Mac/Apple Clipboard?"

        elsif(	e.to_s =~ /The server responded with error: STATUS_NETWORK_ACCESS_DENIED/ or
          e.to_s =~ /The server responded with error: 0x00030001/ or
          e.to_s =~ /The server resposded with error: 0x00060002/
        )
        #0x0006002 = bad network name, 0x0030001 Directory not found
          return false,false,nil,nil
        else
          print_error("\\\\#{ip}\\#{share}: Error querying filesystem device type (#{e})")
          return false,false,nil,nil
        end
    end

    skip = false
    msg = ''
    case device_type
      when -1
        msg = "Unable to determine device"
      when 1, 21 .. 29, 34 .. 35, 37 .. 44
        skip = true
        msg = "Unhandled Device Type (#{device_type})"
      when 2 .. 16, 18 .. 20, 30 .. 33, 36
        msg = device_type_int_to_text(device_type)
      when 17
        skip = true
        msg = device_type_int_to_text(device_type)
      else
        msg = "Unknown Device Type"
        msg << " (#{device_type})" if device_type
    end

    return read,write,msg,nil if(skip)
 
    rfd = self.simple.client.find_first("\\")
    read = true if rfd != nil
    filename = Rex::Text.rand_text_alpha(rand(8)) 
    wfd = simple.open("\\#{filename}", 'rwct')
    wfd << Rex::Text.rand_text_alpha(rand(1024))
    wfd.close
    simple.delete("\\#{filename}")
    simple.disconnect("\\\\#{ip}\\#{share}")
    write = true # Operating under assumption STATUS_ACCESS_DENIED or the like will get thrown before write=true

    return read,write,msg,rfd
  
    rescue ::Rex::Proto::SMB::Exceptions::NoReply,::Rex::Proto::SMB::Exceptions::InvalidType,
      ::Rex::Proto::SMB::Exceptions::ReadPacket,::Rex::Proto::SMB::Exceptions::ErrorCode
      return read,false,msg,rfd
    rescue ::Exception => e
      print_error("Error: '#{ip}' '#{e.class}' '#{e}' '#{e.backtrace}'")
  end # eval host

  def run_host(ip)

    found = false
    [[139, false], [445, true]].each do |info|

    datastore['RPORT'] = info[0]
    datastore['SMBDirect'] = info[1]

    begin
      connect
      smb_login

      res = self.simple.client.trans(
        "\\PIPE\\LANMAN",
        (
          [0x00].pack('v') +
          "WrLeh\x00"   +
          "B13BWz\x00"  +
          [0x01, 65406].pack("vv")
        )
      )

      shares = []

      lerror, lconv, lentries, lcount = res['Payload'].to_s[
        res['Payload'].v['ParamOffset'],
        res['Payload'].v['ParamCount']
      ].unpack("v4")

      data = res['Payload'].to_s[
        res['Payload'].v['DataOffset'],
        res['Payload'].v['DataCount']
      ]

      0.upto(lentries - 1) do |i|
        sname,tmp = data[(i * 20) +  0, 14].split("\x00")
        stype     = data[(i * 20) + 14, 2].unpack('v')[0]
        scoff     = data[(i * 20) + 16, 2].unpack('v')[0]
        if ( lconv != 0)
          scoff -= lconv
        end
        scomm,tmp = data[scoff, data.length - scoff].split("\x00")

        shares << [ sname, share_type(stype), scomm]
      end

      if not shares.empty?
        read = false 
        write = false
        found = true
        os = smb_fingerprint
        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :type => 'smb.shares',
          :data => { :shares => shares },
          :update => :unique_data
        )

        str = "#{shares.map{|x| "#{x[0]}"}.join("\x00")}"
        list = str.split(/\x00/)
        str.gsub!(/\x00/, ', ')
        out = "#{ip}:#{rport}"
        out << " \\\\#{simple.client.default_domain}" if simple.client.default_domain and simple.client.default_name
        out << "\\#{simple.client.default_name}" if simple.client.default_name

        desc = " #{os['os']} #{os['sp']}" if os['os'] != "Unknown"
        desc << " (lang: #{os['lang']})" if os['lang'] != "Unknown"
        out << desc if desc != nil

        report_service(
          :host  => ip,
          :port  => info[0],
          :proto => 'tcp',
          :name  => 'smb',
          :info  => desc
        ) if desc != nil

        print_status(out + ": Found #{shares.length} shares (#{str})")
        list.each do |x|
          read,write,type,files = eval_host(ip, x)
          if(read or write)
            out = "#{ip}"
            out << " \\\\#{simple.client.default_domain}" if simple.client.default_domain and  simple.client.default_name
            out << "\\#{simple.client.default_name}" if simple.client.default_name
            out << "\\#{x} "
            out << " (#{type})" if type != nil
            out << " is readable" if read
            out << " is writable" if write
            first = true
            if datastore['VERBOSE']
              files.each do |file|
                if file[0] != '.' and file[0] != '..' and file[0]
                  fa = file[1]['attr']
                  info = file[1]['info']
                  tcr = ::Time.at(::Rex::Proto::SMB::Utils.time_smb_to_unix(info[3], info[2])).strftime("%m-%d-%Y %H:%M:%S")
                  tac = ::Time.at(::Rex::Proto::SMB::Utils.time_smb_to_unix(info[5], info[4])).strftime("%m-%d-%Y %H:%M:%S")
                  twr = ::Time.at(::Rex::Proto::SMB::Utils.time_smb_to_unix(info[7], info[6])).strftime("%m-%d-%Y %H:%M:%S")
                  tch = ::Time.at(::Rex::Proto::SMB::Utils.time_smb_to_unix(info[9], info[8])).strftime("%m-%d-%Y %H:%M:%S")
                  sz = info[12] + info[13]

                  case fa
                    when 1 
                      fa = "RO"
                    when 2 
                      fa = "HIDDEN"
                    when 4 
                      fa = "SYS"
                    when 8 
                      fa = "VOL"
                    when 16 
                      fa = "DIR"
                    when 32 
                      fa = "ARC"
                    when 64 
                      fa = "DEV"
                    when 128 
                      fa = "FILE"
                  end
                  if first
                    out << "\n"
                    out << sprintf("%-6s %-25s ", "Type" , "Name")
                    out << sprintf("%-21s %-21s %-21s %-21s %-15s\n", "Created", "Accessed", "Written", "Changed", "Size")
                    first = false
                  end

                  out << sprintf("%-6s %-25s ", fa, file[0]) 
                  out << sprintf("%-21s %-21s %-21s %-21s ", tcr,tac,twr,tch)
                  out << "#{sz}\n"
                end
              end
            end
            print_good(out) 
          end	
        end
      end # if shares not empty
      break if found and rport == 139
      rescue ::Interrupt
        raise $!
      rescue 
        next if not found and rport == 139
      rescue ::Rex::ConnectionError,Errno::ECONNRESET,
        ::Rex::Proto::SMB::Exceptions::InvalidType,::Rex::Proto::SMB::Exceptions::ReadPacket,
        ::Rex::Proto::SMB::Exceptions::LoginError,::Rex::Proto::SMB::Exceptions::InvalidCommand,
        ::Rex::Proto::SMB::Exceptions::ErrorCode,::Rex::Proto::SMB::Exceptions::InvalidWordCount,
 				::Rex::Proto::SMB::Exceptions::NoReply => e
        next if not found and rport == 139		# no results, try again
      rescue Errno::ENOPROTOOPT
        sleep 5
        retry
      rescue ::Exception => e
        next if(e.to_s =~ /execution expired/) 
        print_error("Error: '#{ip}' '#{e.class}' '#{e}' '#{e.backtrace}'")

    end # begin
    return if(rport == 139 and found ) # if we already got results on 139, no need to try 445
    end # each info
    disconnect
    return
  end # run_host
end

