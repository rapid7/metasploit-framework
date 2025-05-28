##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

  ATTRIBUTE = 'unicodePwd'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Change Password',
        'Description' => %q{
          This module allows Active Directory users to change their own passwords, or reset passwords for
          accounts they have privileges over.
        },
        'Author' => [
          'smashery' # module author
        ],
        'References' => [
          ['URL', 'https://github.com/fortra/impacket/blob/master/examples/changepasswd.py'],
          ['URL', 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2'],
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['RESET', { 'Description' => "Reset a target user's password, having permissions over their account" }],
          ['CHANGE', { 'Description' => "Change the user's password, knowing the existing password" }]
        ],
        'DefaultAction' => 'RESET',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGET_USER', [false, 'The user to reset the password of.'], conditions: ['ACTION', 'in', %w[RESET]]),
      OptString.new('NEW_PASSWORD', [ true, 'The new password to set for the user' ])
    ])
  end

  def fail_with_ldap_error(message)
    ldap_result = @ldap.get_operation_result.table
    return if ldap_result[:code] == 0

    print_error(message)
    if ldap_result[:code] == 19
      extra_error = ''
      if action.name == 'CHANGE' && !datastore['SESSION'].blank?
        # If you're already in a session, you could provide the wrong password, and you get this error
        extra_error = ' or incorrect current password'
      end

      error = "The password change failed, likely due to a password policy violation (e.g. not sufficiently complex, matching previous password, or changing the password too often)#{extra_error}"
      fail_with(Failure::NotFound, error)
    else
      validate_query_result!(ldap_result)
    end
  end

  def ldap_get(filter, attributes: [])
    raw_obj = @ldap.search(base: @base_dn, filter: filter, attributes: attributes)&.first
    return nil unless raw_obj

    obj = {}

    obj['dn'] = raw_obj['dn'].first.to_s
    unless raw_obj['sAMAccountName'].empty?
      obj['sAMAccountName'] = raw_obj['sAMAccountName'].first.to_s
    end

    obj
  end

  def run
    if action.name == 'CHANGE'
      fail_with(Failure::BadConfig, 'Must set LDAPUsername when changing password') if datastore['LDAPUsername'].blank?
      fail_with(Failure::BadConfig, 'Must set LDAPPassword when changing password') if datastore['LDAPPassword'].blank?
    elsif action.name == 'RESET'
      fail_with(Failure::BadConfig, 'Must set TARGET_USER when resetting password') if datastore['TARGET_USER'].blank?
    end
    if session.blank? && datastore['LDAPUsername'].blank? && datastore['LDAP::Auth'] != Msf::Exploit::Remote::AuthOption::SCHANNEL
      print_warning('Connecting with an anonymous bind')
    end
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        if (@base_dn = ldap.base_dn)
          print_status("#{ldap.peerinfo} Discovered base DN: #{@base_dn}")
        else
          fail_with(Failure::UnexpectedReply, "Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      begin
        send("action_#{action.name.downcase}")
      rescue ::IOError => e
        fail_with(Failure::UnexpectedReply, e.message)
      end
    end
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::NoAccess, e.message)
  rescue Rex::Proto::LDAP::LdapException => e
    fail_with(Failure::NoAccess, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def get_user_obj(username)
    obj = ldap_get("(sAMAccountName=#{ldap_escape_filter(username)})", attributes: ['sAMAccountName'])
    fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{username}") unless obj

    obj
  end

  def action_reset
    target_user = datastore['TARGET_USER']
    obj = get_user_obj(target_user)

    new_pass = "\"#{datastore['NEW_PASSWORD']}\"".encode('utf-16le').bytes.pack('c*')
    unless @ldap.replace_attribute(obj['dn'], ATTRIBUTE, new_pass)
      fail_with_ldap_error("Failed to reset the password for #{datastore['TARGET_USER']}.")
    end
    print_good("Successfully reset password for #{datastore['TARGET_USER']}.")
  end

  def action_change
    obj = get_user_obj(datastore['LDAPUsername'])

    new_pass = "\"#{datastore['NEW_PASSWORD']}\"".encode('utf-16le').bytes.pack('c*')
    old_pass = "\"#{datastore['LDAPPassword']}\"".encode('utf-16le').bytes.pack('c*')
    unless @ldap.modify(dn: obj['dn'], operations: [[:delete, ATTRIBUTE, old_pass], [:add, ATTRIBUTE, new_pass]])
      fail_with_ldap_error("Failed to change the password for #{datastore['LDAPUsername']}.")
    end
    print_good("Successfully changed password for #{datastore['LDAPUsername']}.")
  end
end
