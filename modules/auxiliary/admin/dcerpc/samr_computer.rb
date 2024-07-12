##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::MsSamr::Computer
  include Msf::OptionalSession::SMB

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SAMR Computer Management',
        'Description' => %q{
          Add, lookup and delete computer / machine accounts via MS-SAMR. By default
          standard active directory users can add up to 10 new computers to the
          domain. Administrative privileges however are required to delete the
          created accounts.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'JaGoTu', # @jagotu Original Impacket code
          'Spencer McIntyre',
        ],
        'References' => [
          ['URL', 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py'],
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'ADD_COMPUTER', { 'Description' => 'Add a computer account' } ],
          [ 'DELETE_COMPUTER', { 'Description' => 'Delete a computer account' } ],
          [ 'LOOKUP_COMPUTER', { 'Description' => 'Lookup a computer account' } ]
        ],
        'DefaultAction' => 'ADD_COMPUTER'
      )
    )

    register_options([
      OptString.new('COMPUTER_PASSWORD', [ false, 'The password for the new computer' ], conditions: %w[ACTION == ADD_COMPUTER]),
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
  end

  def action_add_computer
    with_ipc_tree do |opts|
      add_computer(opts)
    end
  end

  def action_delete_computer
    fail_with(Failure::BadConfig, 'This action requires COMPUTER_NAME to be specified.') if datastore['COMPUTER_NAME'].blank?
    with_ipc_tree do |opts|
      delete_computer(opts)
    end
  end

  def action_lookup_computer
    fail_with(Failure::BadConfig, 'This action requires COMPUTER_NAME to be specified.') if datastore['COMPUTER_NAME'].blank?
    with_ipc_tree do |opts|
      lookup_computer(opts)
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
