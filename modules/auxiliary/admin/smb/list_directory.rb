##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::Client
  XCEPT = Rex::Proto::SMB::Exceptions
  CONST = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name' => 'SMB Directory Listing Utility',
      'Description' => %(
        This module lists the directory of a target share and path. The only reason
      to use this module is if your existing SMB client is not able to support the features
      of the Metasploit Framework that you need, like pass-the-hash authentication.
      ),
      'Author' => [
        'mubix',
        'hdm'
      ],
      'References' => [
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('RPATH', [false, 'The name of the remote directory relative to the share']),
    ])

    deregister_options('SMB::ProtocolVersion')
  end

  def as_size(size)
    prefix = %w[TB GB MB KB B]
    size = size.to_f
    i = prefix.length - 1
    while size > 512 && i > 0
      size /= 1024
      i -= 1
    end
    ((size > 9 || size.modulo(1) < 0.1 ? '%d' : '%.1f') % size) + ' ' + prefix[i]
  end

  def run
    print_status('Connecting to the server...')
    connect(versions: [1])
    smb_login
    print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    simple.connect("\\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}")
    if datastore['RPATH']
      print_status("Listing \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}'...")
    end
    listing = simple.client.find_first("\\#{datastore['RPATH']}\\*")
    directory = Rex::Text::Table.new(
      'Header' => "Directory Listing of \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}",
      'Indent' => 2,
      'SortIndex' => 2,
      'Columns' => ['SIZE', 'TYPE', 'TIME', 'FILENAME']
    )
    listing.each_pair do |key, val|
      file_lastmodified = ::Time.at(Rex::Proto::SMB::Utils.time_smb_to_unix(val['info'][9], val['info'][10]))
      size = val['info'][10]
      if val['attr'] == 16
        size = ''
      else
        'FILE'
      end
      directory << [as_size(size.to_s), val['type'], file_lastmodified.strftime('%Y-%m-%d %H:%m:%S%p'), key]
    end
    print_status(directory.to_s)
  rescue Rex::Proto::SMB::Exceptions::Error => e
    # SMB has very good explanations in error messages, don't really need to
    # prefix with anything here.
    print_error(e.to_s)
  end
end
