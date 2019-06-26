##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'aws-sdk-iam'

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Amazon Web Services IAM credential enumeration',
        'Description' => %q(
                          Provided AWS credentials, this module will call the authenticated
                          API of Amazon Web Services to list all IAM credentials associated
                          with the account
                         ),
        'Author'      => ['Aaron Soto <aaron.soto@rapid7.com>'],
        'License'     => MSF_LICENSE
      )
    )

    register_options(
      [
        OptString.new('ACCESS_KEY_ID', [true, 'AWS Access Key ID (eg. "AKIAXXXXXXXXXXXXXXXX")', '']),
        OptString.new('SECRET_ACCESS_KEY', [true, 'AWS Secret Access Key (eg. "CA1+XXXXXXXXXXXXXXXXXXXXXX6aYDHHCBuLuV79")', ''])
      ]
    )
  end

  def handle_aws_errors(e)
    if e.class.parents.include?(Aws)
      fail_with(Failure::UnexpectedReply, e.message)
    else
      raise e
    end
  end

  def describe_iam_users(i)
    user = i.user_name

    print_good "  User Name:       #{user}"
    print_good "  User ID:         #{i.user_id}"
    print_good "  Creation Date:   #{i.create_date}"
    print_good "  Tags:            #{i.tags}"
    print_good "  Groups:          #{i.group_list}"
    print_good "  SSH Pub Keys:    #{@iam.list_ssh_public_keys(user_name: user).ssh_public_keys}"

    policies = i.attached_managed_policies
    if policies.empty?
      print_good "  Policies:        []"
    else
      print_good "  Policies:        #{policies[0].policy_name}"
      policies[1..policies.length].each do |p|
        print_good "                   #{p.policy_name}"
      end
    end

    certs = @iam.list_signing_certificates(user_name: user).certificates
    if certs.empty?
      print_good "  Signing certs:   []"
    else
      print_good "  Signing certs:   #{certs[0].certificate_id} (#{certs[0].status})"
      certs[1..certs.length].each do |c|
        print_good "                   #{c.certificate_id} (#{c.status})"
      end
    end

    @users.each do |u|
      if u.user_name == user
        print_good "  Password Used:   #{u.password_last_used || '(Never)'}"
      end
    end

    keys = @iam.list_access_keys(user_name: user).access_key_metadata
    if keys.empty?
      print_good "  AWS Access Keys: []"
    else
      print_good "  AWS Access Keys: #{keys[0].access_key_id} (#{keys[0].status})"
      keys[1..keys.length].each do |k|
        print_good "                   #{k.access_key_id} (#{k.status})"
      end
    end

    begin
      console_login = @iam.get_login_profile(user_name: user).empty? ? 'Disabled' : 'Enabled'
      print_good "  Console login:   #{console_login}"
    rescue Aws::IAM::Errors::NoSuchEntity
      print_good "  Console login:   Disabled"
    end

    mfa = @iam.list_mfa_devices(user_name: i.user_name).mfa_devices
    mfa_enabled = mfa.empty? ? 'Disabled' : "Enabled on #{mfa[0].enable_date}"
    print_good "  Two-factor auth: #{mfa_enabled}"

    print_status ''
  end

  def run
    @iam = Aws::IAM::Client.new(
      region: 'us-west-1',      # This is meaningless, but required.  Thanks AWS.
      access_key_id: datastore['ACCESS_KEY_ID'],
      secret_access_key: datastore['SECRET_ACCESS_KEY']
    )

    @users = @iam.list_users.users
    creds = @iam.get_account_authorization_details

    users = creds.user_detail_list
    if users.empty?
      print_status 'No users found.'
      return
    end

    print_good "Found #{users.count} users."
    users.each do |i|
      describe_iam_users(i)
    end
  rescue ::Exception => e
    handle_aws_errors(e)
  end
end
