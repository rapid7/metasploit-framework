###
#
# This mixin provides methods to add, delete and lookup accounts via MS-SAMR
#
# -*- coding: binary -*-

module Msf

module Exploit::Remote::MsSamr::Account

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::MsSamr

  AccountInfo = Struct.new(:name, :password)

  def initialize(info = {})
    super

    register_options([
      OptString.new('ACCOUNT_NAME', [ false, 'The account name' ]),
      OptString.new('ACCOUNT_PASSWORD', [ false, 'The password for the new account' ]),
    ], Msf::Exploit::Remote::MsSamr)
  end

  def generate_unused_computer_name(samr_con)
    computer_name = random_hostname
    4.downto(0) do |attempt|
      break if samr_con.samr.samr_lookup_names_in_domain(
        domain_handle: samr_con.domain_handle,
        names: [ computer_name ]
      ).nil?

      computer_name = random_hostname
      raise MsSamrBadConfigError, 'Could not find an unused computer name.' if attempt == 0
    end

    computer_name
  end

  def validate_name_doesnt_exist(samr_con, name)
    if samr_con.samr.samr_lookup_names_in_domain(domain_handle: samr_con.domain_handle, names: [ name ])
      raise MsSamrBadConfigError, 'The specified name already exists.'
    end
  end

  # Add a new account (computer or user)
  # @param account_type [Symbol] The type (:computer or :user) of account to create
  def add_account(account_type, opts = {})
    raise MsSamrBadConfigError, 'Must specify computer or user account' unless [:computer, :user].include?(account_type)

    tree = opts[:tree] || connect_ipc

    samr_con = connect_samr(tree)

    account_name = opts[:account_name] || datastore['ACCOUNT_NAME']
    if account_name.blank?
      if account_type == :computer
        account_name = generate_unused_computer_name(samr_con)
      else
        raise MsSamrBadConfigError, 'Must provide a user name'
      end
    else
      validate_name_doesnt_exist(samr_con, account_name)
    end

    account_password = opts[:account_password] || datastore['ACCOUNT_PASSWORD']
    if account_password.blank?
      account_password = Rex::Text.rand_text_alphanumeric(32)
    end

    uac = account_type == :computer ? RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT : RubySMB::Dcerpc::Samr::USER_NORMAL_ACCOUNT

    result = samr_con.samr.samr_create_user2_in_domain(
      domain_handle: samr_con.domain_handle,
      name: account_name,
      account_type: uac,
      desired_access: RubySMB::Dcerpc::Samr::USER_FORCE_PASSWORD_CHANGE | RubySMB::Dcerpc::Samr::MAXIMUM_ALLOWED
    )

    user_handle = result[:user_handle]
    password_expired = (account_type == :computer) ? 1 : 0
    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_INTERNAL4_INFORMATION_NEW,
      member: RubySMB::Dcerpc::Samr::SamprUserInternal4InformationNew.new(
        i1: {
          password_expired: password_expired,
          which_fields: RubySMB::Dcerpc::Samr::USER_ALL_NTPASSWORDPRESENT | RubySMB::Dcerpc::Samr::USER_ALL_PASSWORDEXPIRED,
        },
        user_password: {
          buffer: RubySMB::Dcerpc::Samr::SamprEncryptedUserPasswordNew.encrypt_password(
            account_password,
            @simple.client.application_key
          )
        }
      )
    )
    samr_con.samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
      member: RubySMB::Dcerpc::Samr::UserControlInformation.new(
        user_account_control: uac
      )
    )
    samr_con.samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )
    print_good("Successfully created #{samr_con.domain_name}\\#{account_name}")
    print_good("  Password: #{account_password}")
    print_good("  SID:      #{get_account_sid(samr_con, account_name)}")
    report_creds(samr_con.domain_name, account_name, account_password)

    AccountInfo.new(account_name, account_password)
  rescue RubySMB::Dcerpc::Error::SamrError => e
    raise MsSamrUnknownError, "A DCERPC SAMR error occurred: #{e.message}"
  ensure
    if samr_con
      samr_con.samr.close_handle(user_handle) if user_handle
      samr_con.samr.close_handle(samr_con.domain_handle) if samr_con.domain_handle
      samr_con.samr.close_handle(samr_con.server_handle) if samr_con.server_handle
    end
  end

  def delete_account(opts = {})
    tree = opts[:tree] || connect_ipc

    samr_con = connect_samr(tree)

    account_name = opts[:account_name] || datastore['ACCOUNT_NAME']
    if account_name.blank?
      raise MsSamrBadConfigError, 'Unable to delete the account since its name is unknown'
    end

    details = samr_con.samr.samr_lookup_names_in_domain(domain_handle: samr_con.domain_handle, names: [ account_name ])
    raise MsSamrBadConfigError, 'The specified account was not found.' if details.nil?
    details = details[account_name]

    user_handle = samr_con.samr.samr_open_user(domain_handle: samr_con.domain_handle, user_id: details[:rid])
    samr_con.samr.samr_delete_user(user_handle: user_handle)
    print_good('The specified account has been deleted.')
  rescue RubySMB::Dcerpc::Error::SamrError => e
    # `user_handle` only needs to be closed if an error occurs in `samr_delete_user`
    # If this method succeed, the server took care of closing the handle
    samr_con.samr.close_handle(user_handle) if user_handle
    raise MsSamrUnknownError, "Could not delete the account #{account_name}: #{e.message}"
  ensure
    if samr_con
      samr_con.samr.close_handle(samr_con.domain_handle) if samr_con.domain_handle
      samr_con.samr.close_handle(samr_con.server_handle) if samr_con.server_handle
    end
  end

  def lookup_account(opts = {})
    tree = opts[:tree] || connect_ipc

    samr_con = connect_samr(tree)

    account_name = opts[:account_name] || datastore['ACCOUNT_NAME']
    if account_name.blank?
      raise MsSamrBadConfigError, 'Unable to lookup the account since its name is unknown'
    end

    sid = get_account_sid(samr_con, account_name)
    print_good("Found #{samr_con.domain_name}\\#{account_name} (SID: #{sid})")
  ensure
    if samr_con
      samr_con.samr.close_handle(samr_con.domain_handle) if samr_con.domain_handle
      samr_con.samr.close_handle(samr_con.server_handle) if samr_con.server_handle
    end
  end

  module_function

  def random_hostname(prefix: 'DESKTOP')
    "#{prefix}-#{Rex::Text.rand_base(8, '', ('A'..'Z').to_a + ('0'..'9').to_a)}$"
  end

  def get_account_sid(samr_con, account_name)
    details = samr_con.samr.samr_lookup_names_in_domain(
      domain_handle: samr_con.domain_handle,
      names: [ account_name ]
    )
    raise MsSamrNotFoundError, 'The account was not found.' if details.nil?

    details = details[account_name]
    samr_con.samr.samr_rid_to_sid(
      object_handle: samr_con.domain_handle,
      rid: details[:rid]
    ).to_s
  end

  def report_creds(domain, username, password)
    service_data = {
      address: rhost,
      port: rport,
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
end
