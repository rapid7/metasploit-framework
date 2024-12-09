## # This module requires Metasploit: https://metasploit.com/download # Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SMB Password Change',
        'Description' => %q{
          Change the password of an account using SMB. This provides several different
          APIs, each of which have their respective benefits and drawbacks.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'smashery'
        ],
        'References' => [
          ['URL', 'https://github.com/fortra/impacket/blob/master/examples/changepasswd.py'],
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'RESET', { 'Description' => "Reset the target's password without knowing the existing one (requires appropriate permissions). New AES kerberos keys will be generated." } ],
          [ 'RESET_NTLM', { 'Description' => "Reset the target's NTLM hash, without knowing the existing password. AES kerberos authentication will not work until a standard password change occurs." } ],
          [ 'CHANGE', { 'Description' => 'Change the password, knowing the existing one. New AES kerberos keys will be generated.' } ],
          [ 'CHANGE_NTLM', { 'Description' => 'Change the password to a NTLM hash value, knowing the existing password. AES kerberos authentication will not work until a standard password change occurs.' } ]
        ],
        'DefaultAction' => 'RESET'
      )
    )

    register_options(
      [
        OptString.new('NEW_PASSWORD', [false, 'The new password to change to', ''], conditions: ['ACTION', 'in', %w[CHANGE RESET]]),
        OptString.new('NEW_NTLM', [false, 'The new NTLM hash to change to. Can be either an NT hash or a colon-delimited NTLM hash'], conditions: ['ACTION', 'in', %w[CHANGE_NTLM RESET_NTLM]], regex: /^([0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$/),
        OptString.new('TARGET_USER', [false, 'The user to reset the password of.'], conditions: ['ACTION', 'in', %w[RESET RESET_NTLM]])
      ]
    )
  end

  def connect_samr
    vprint_status('Connecting to Security Account Manager (SAM) Remote Protocol')
    @samr = @tree.open_file(filename: 'samr', write: true, read: true)

    vprint_status('Binding to \\samr...')
    @samr.bind(endpoint: RubySMB::Dcerpc::Samr)
    vprint_good('Bound to \\samr')
  end

  def run
    case action.name
    when 'CHANGE'
      run_change
    when 'RESET'
      run_reset
    when 'RESET_NTLM'
      run_reset_ntlm
    when 'CHANGE_NTLM'
      run_change_ntlm
    end
  rescue RubySMB::Error::RubySMBError => e
    fail_with(Module::Failure::UnexpectedReply, "[#{e.class}] #{e}")
  rescue Rex::ConnectionError => e
    fail_with(Module::Failure::Unreachable, "[#{e.class}] #{e}")
  rescue Msf::Exploit::Remote::MsSamr::MsSamrError => e
    fail_with(Module::Failure::BadConfig, "[#{e.class}] #{e}")
  rescue ::StandardError => e
    raise e
  ensure
    @samr.close_handle(@domain_handle) if @domain_handle
    @samr.close_handle(@server_handle) if @server_handle
    @samr.close if @samr
    @tree.disconnect! if @tree

    # Don't disconnect the client if it's coming from the session so it can be reused
    unless session
      simple.client.disconnect! if simple&.client.is_a?(RubySMB::Client)
      disconnect
    end
  end

  def authenticate(anonymous_on_expired: false)
    if session
      print_status("Using existing session #{session.sid}")
      client = session.client
      self.simple = ::Rex::Proto::SMB::SimpleClient.new(client.dispatcher.tcp_socket, client: client)
      simple.connect("\\\\#{simple.address}\\IPC$") # smb_login connects to this share for some reason and it doesn't work unless we do too
    else
      connect
      begin
        begin
          smb_login
        rescue Rex::Proto::SMB::Exceptions::LoginError => e
          if (e.source.is_a?(Rex::Proto::Kerberos::Model::Error::KerberosError) && [Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_KEY_EXPIRED].include?(e.source.error_code) ||
              e.source.is_a?(::WindowsError::ErrorCode) && [::WindowsError::NTStatus::STATUS_PASSWORD_EXPIRED, ::WindowsError::NTStatus::STATUS_PASSWORD_MUST_CHANGE].include?(e.source))
            if anonymous_on_expired
              # Password has expired - we'll need to anonymous connect
              print_warning('Password expired - binding anonymously')
              opts = {
                username: '',
                password: '',
                domain: '',
                auth_protocol: Msf::Exploit::Remote::AuthOption::NTLM
              }
              disconnect
              connect
              smb_login(opts: opts)
            elsif action.name == 'CHANGE_NTLM'
              fail_with(Module::Failure::UnexpectedReply, 'Must change password first. Try using the CHANGE action instead')
            else
              raise
            end
          else
            raise
          end
        end
      rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
        fail_with(Module::Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
      end
    end

    report_service(
      host: simple.address,
      port: simple.port,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      @tree = simple.client.tree_connect("\\\\#{simple.address}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable,
                "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    connect_samr
  end

  def parse_ntlm_from_config
    new_ntlm = datastore['NEW_NTLM']
    fail_with(Msf::Exploit::Failure::BadConfig, 'Must provide NEW_NTLM value') if new_ntlm.blank?
    case new_ntlm.count(':')
    when 0
      new_nt = new_ntlm
      new_lm = nil
    when 1
      new_lm, new_nt = new_ntlm.split(':')
    else
      fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid value for NEW_NTLM')
    end

    new_nt = Rex::Text.hex_to_raw(new_nt)
    new_lm = Rex::Text.hex_to_raw(new_lm) unless new_lm.nil?
    fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid NT hash value in NEW_NTLM') unless new_nt.length == 16
    fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid LM hash value in NEW_NTLM') unless new_lm.nil? || new_nt.length == 16

    [new_nt, new_lm]
  end

  def get_user_handle(domain, username)
    vprint_status("Opening handle for #{domain}\\#{username}")
    @server_handle = @samr.samr_connect
    domain_sid = @samr.samr_lookup_domain(server_handle: @server_handle, name: domain)
    @domain_handle = @samr.samr_open_domain(server_handle: @server_handle, domain_id: domain_sid)
    user_rids = @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [username])
    fail_with(Module::Failure::BadConfig, "Could not find #{domain}\\#{username}") if user_rids.nil?
    rid = user_rids[username][:rid]

    @samr.samr_open_user(domain_handle: @domain_handle, user_id: rid)
  rescue RubySMB::Dcerpc::Error::SamrError => e
    fail_with(Msf::Exploit::Failure::BadConfig, e.to_s)
  end

  def run_change_ntlm
    fail_with(Module::Failure::BadConfig, 'Must set NEW_NTLM') if datastore['NEW_NTLM'].blank?
    fail_with(Module::Failure::BadConfig, 'Must set SMBUser to change password') if datastore['SMBUser'].blank?
    fail_with(Module::Failure::BadConfig, 'Must set SMBPass to change password, or use RESET/RESET_NTLM to force-change a password without knowing the existing password') if datastore['SMBPass'].blank?
    new_nt, new_lm = parse_ntlm_from_config
    print_status('Changing NTLM')
    authenticate(anonymous_on_expired: false)

    user_handle = get_user_handle(datastore['SMBDomain'], datastore['SMBUser'])

    if Net::NTLM.is_ntlm_hash?(Net::NTLM::EncodeUtil.encode_utf16le(datastore['SMBPass']))
      old_lm, old_nt = datastore['SMBPass'].split(':')
      old_lm = [old_lm].pack('H*')
      old_nt = [old_nt].pack('H*')

      @samr.samr_change_password_user(user_handle: user_handle,
                                      new_nt_hash: new_nt,
                                      new_lm_hash: new_lm,
                                      old_nt_hash: old_nt,
                                      old_lm_hash: old_lm)
    else
      @samr.samr_change_password_user(user_handle: user_handle,
                                      old_password: datastore['SMBPass'],
                                      new_nt_hash: new_nt,
                                      new_lm_hash: new_lm)
    end

    print_good("Successfully changed password for #{datastore['SMBUser']}")
    print_warning('AES Kerberos keys will not be available until user changes their password')
  end

  def run_reset_ntlm
    fail_with(Module::Failure::BadConfig, "Must set TARGET_USER, or use CHANGE/CHANGE_NTLM to reset this user's own password") if datastore['TARGET_USER'].blank?
    new_nt, = parse_ntlm_from_config
    print_status('Resetting NTLM')
    authenticate(anonymous_on_expired: false)

    user_handle = get_user_handle(datastore['SMBDomain'], datastore['TARGET_USER'])

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_INTERNAL1_INFORMATION,
      member: RubySMB::Dcerpc::Samr::SamprUserInternal1Information.new(
        encrypted_nt_owf_password: RubySMB::Dcerpc::Samr::EncryptedNtOwfPassword.new(buffer: RubySMB::Dcerpc::Samr::EncryptedNtOwfPassword.encrypt_hash(hash: new_nt, key: simple.client.application_key)),
        encrypted_lm_owf_password: nil,
        nt_password_present: 1,
        lm_password_present: 0,
        password_expired: 0
      )
    )
    @samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )

    print_good("Successfully reset password for #{datastore['TARGET_USER']}")
    print_warning('AES Kerberos keys will not be available until user changes their password')
  end

  def run_reset
    fail_with(Module::Failure::BadConfig, "Must set TARGET_USER, or use CHANGE/CHANGE_NTLM to reset this user's own password") if datastore['TARGET_USER'].blank?
    fail_with(Module::Failure::BadConfig, 'Must set NEW_PASSWORD') if datastore['NEW_PASSWORD'].blank?
    print_status('Resetting password')
    authenticate(anonymous_on_expired: false)

    user_handle = get_user_handle(datastore['SMBDomain'], datastore['TARGET_USER'])

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_INTERNAL4_INFORMATION_NEW,
      member: RubySMB::Dcerpc::Samr::SamprUserInternal4InformationNew.new(
        i1: {
          password_expired: 0,
          which_fields: RubySMB::Dcerpc::Samr::USER_ALL_NTPASSWORDPRESENT | RubySMB::Dcerpc::Samr::USER_ALL_PASSWORDEXPIRED
        },
        user_password: {
          buffer: RubySMB::Dcerpc::Samr::SamprEncryptedUserPasswordNew.encrypt_password(
            datastore['NEW_PASSWORD'],
            simple.client.application_key
          )
        }
      )
    )
    @samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )
    print_good("Successfully reset password for #{datastore['TARGET_USER']}")
  end

  def run_change
    fail_with(Module::Failure::BadConfig, 'Must set NEW_PASSWORD') if datastore['NEW_PASSWORD'].blank?
    fail_with(Module::Failure::BadConfig, 'Must set SMBUser to change password') if datastore['SMBUser'].blank?
    fail_with(Module::Failure::BadConfig, 'Must set SMBPass to change password, or use RESET/RESET_NTLM to force-change a password without knowing the existing password') if datastore['SMBPass'].blank?
    print_status('Changing password')
    authenticate(anonymous_on_expired: true)

    if Net::NTLM.is_ntlm_hash?(Net::NTLM::EncodeUtil.encode_utf16le(datastore['SMBPass']))
      old_lm, old_nt = datastore['SMBPass'].split(':')
      old_lm = [old_lm].pack('H*')
      old_nt = [old_nt].pack('H*')
      @samr.samr_unicode_change_password_user2(target_username: datastore['SMBUser'], new_password: datastore['NEW_PASSWORD'], old_nt_hash: old_nt, old_lm_hash: old_lm)
    else
      @samr.samr_unicode_change_password_user2(target_username: datastore['SMBUser'], old_password: datastore['SMBPass'], new_password: datastore['NEW_PASSWORD'])
    end

    print_good("Successfully changed password for #{datastore['SMBUser']}")
  end
end
