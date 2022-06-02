##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SAMR Computer Management',
        'Description' => %q{
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Alberto Solino', # Original Impacket code # todo: verify this author credit
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
          [ 'ADD', { 'Description' => 'Add a computer account' } ],
        ],
        'DefaultAction' => 'ADD'
      )
    )

    register_options([ Opt::RPORT(445) ])
  end

  def connect_samr
    vprint_status('Connecting to Security Account Manager (SAM) Remote Protocol')
    samr = @tree.open_file(filename: 'samr', write: true, read: true)

    vprint_status('Binding to \\samr...')
    samr.bind(endpoint: RubySMB::Dcerpc::Samr)
    vprint_good('Bound to \\samr')

    samr
  end

  def run
    connect
    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    end
    report_service(
      host: rhost,
      port: rport,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    samr = connect_samr
    server_handle = samr.samr_connect(access: 0x30)
    domains = samr.samr_enumerate_domains_in_sam_server(server_handle: server_handle)
    print_status(domains.inspect)
  end
end
