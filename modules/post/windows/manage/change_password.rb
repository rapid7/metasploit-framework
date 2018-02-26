##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage Change Password",
      'Description'          => %q{
        This module will attempt to change the password of the targeted account.
        The typical usage is to change a newly created account's password on a
        remote host to avoid the error, 'System error 1907 has occurred,' which
        is caused when the account policy enforces a password change before the
        next login.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['Ben Campbell']
    ))

    register_options(
      [
        OptString.new('SMBDomain', [false, 'Domain or Host to change password on, if not set will use the current login domain', nil]),
        OptString.new('SMBUser', [true, 'Username to change password of']),
        OptString.new('OLD_PASSWORD', [true, 'Original password' ]),
        OptString.new('NEW_PASSWORD', [true, 'New password' ]),
      ])
  end

  def run
    unless client.railgun
      print_error('This module requires a native Windows payload that supports Railgun.')
      return
    end

    domain = datastore['SMBDomain']
    username = datastore['SMBUser']
    old_password = datastore['OLD_PASSWORD']
    new_password = datastore['NEW_PASSWORD']
    print_status("Changing #{domain}\\#{username} password to #{new_password}...")
    result = client.railgun.netapi32.NetUserChangePassword(
      domain,
      username,
      old_password,
      new_password
    )

    case result['return']
    when 0x05
      err_msg = 'ERROR_ACCESS_DENIED'
    when 0x56
      err_msg = 'ERROR_INVALID_PASSWORD'
    when 0x92f
      err_msg = 'NERR_InvalidComputer'
    when 0x8b2
      err_msg = 'NERR_NotPrimary'
    when 0x8ad
      err_msg = 'NERR_UserNotFound'
    when 0x8c5
      err_msg = 'NERR_PasswordTooShort'
    when 0
      print_good('Password change successful.')
    else
      err_msg = "unknown error code: #{result['return']}"
    end

    if err_msg
      print_error("Password change failed, #{err_msg}.")
    end

  end
end

