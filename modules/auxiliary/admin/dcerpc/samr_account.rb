##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::MsSamr::Account
  include Msf::OptionalSession::SMB
  include Msf::Exploit::Deprecated

  moved_from 'auxiliary/admin/dcerpc/samr_computer'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SAMR Account Management',
        'Description' => %q{
          Add, lookup and delete user / machine accounts via MS-SAMR. By default
          standard active directory users can add up to 10 new computers to the
          domain (MachineAccountQuota). Administrative privileges however are required
          to delete the created accounts, or to create/delete user accounts.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'JaGoTu', # @jagotu Original Impacket code
          'Spencer McIntyre',
          'smashery'
        ],
        'References' => [
          ['URL', 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py'],
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ],
          'AKA' => ['samr_computer', 'samr_user']
        },
        'Actions' => [
          [ 'ADD_COMPUTER', { 'Description' => 'Add a computer account' } ],
          [ 'ADD_USER', { 'Description' => 'Add a user account' } ],
          [ 'DELETE_ACCOUNT', { 'Description' => 'Delete a computer or user account' } ],
          [ 'LOOKUP_ACCOUNT', { 'Description' => 'Lookup a computer or user account' } ]
        ],
        'DefaultAction' => 'ADD_COMPUTER'
      )
    )

    register_options([
      Opt::RPORT(445)
    ])
  end

  def run
    send("action_#{action.name.downcase}")
  rescue MsSamrConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue MsSamrAuthenticationError => e
    fail_with(Failure::NoAccess, e.message)
  rescue MsSamrNotFoundError => e
    fail_with(Failure::NotFound, e.message)
  rescue MsSamrBadConfigError => e
    fail_with(Failure::BadConfig, e.message)
  rescue MsSamrUnexpectedReplyError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue MsSamrUnknownError => e
    fail_with(Failure::Unknown, e.message)
  rescue SmbIpcAuthenticationError => e
    fail_with(Failure::Unknown, e.message)
  end

  def action_add_user
    fail_with(Failure::BadConfig, 'This action requires ACCOUNT_NAME to be specified.') if datastore['ACCOUNT_NAME'].blank?
    print_status('Adding user')
    with_ipc_tree do |opts|
      add_account(:user, opts)
    end
  end

  def action_add_computer
    print_status('Adding computer')
    with_ipc_tree do |opts|
      add_account(:computer, opts)
    end
  end

  def action_delete_account
    fail_with(Failure::BadConfig, 'This action requires ACCOUNT_NAME to be specified.') if datastore['ACCOUNT_NAME'].blank?
    with_ipc_tree do |opts|
      delete_account(opts)
    end
  end

  def action_lookup_account
    fail_with(Failure::BadConfig, 'This action requires ACCOUNT_NAME to be specified.') if datastore['ACCOUNT_NAME'].blank?
    with_ipc_tree do |opts|
      lookup_account(opts)
    end
  end

  # @yieldparam options [Hash] If a SMB session is present, a hash with the IPC tree present. Empty hash otherwise.
  # @return [void]
  def with_ipc_tree
    opts = {}
    if session
      print_status("Using existing session #{session.sid}")
      client = session.client
      self.simple = ::Rex::Proto::SMB::SimpleClient.new(client.dispatcher.tcp_socket, client: client)
      opts[:tree] = simple.client.tree_connect("\\\\#{client.dispatcher.tcp_socket.peerhost}\\IPC$")
    end

    yield opts
  ensure
    opts[:tree].disconnect! if opts[:tree]
  end
end
