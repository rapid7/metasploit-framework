##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage Change Password",
      'Description'          => %q{
        This module will attempt to change the password of the targetted account.
        Its main purpose is when you have valid credentials on a remote host but
        they require a password change before you can login e.g.
        'System error 1907 has occurred.'
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
      ], self.class)
  end

  def run
    unless client.railgun
      print_error('This module requires a native windows payload that supports railgun.')
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
      report_creds(username, new_password, domain)
    else
      err_msg = "unknown error code: #{result['return']}"
    end

    if err_msg
      print_error("Password change failed, #{err_msg}.")
    end

  end

  def report_creds(user, pass, domain)
    if session.db_record
      source_id = session.db_record.id
    else
      source_id = nil
    end

    unless domain
      domain = session.sock.peerhost
    end

    report_auth_info(
      :host  => domain,
      :port => 445,
      :sname => 'smb',
      :proto => 'tcp',
      :source_id => source_id,
      :source_type => "exploit",
      :user => user,
      :pass => pass)
  end
end

