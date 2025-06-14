##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  SID_PREFIX_USER = 'S-1-5-21-'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather SMB Share Enumeration via Registry',
        'Description' => %q{ This module will enumerate configured and recently used file shares. },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
        'Platform' => [ 'win' ],
        'SessionTypes' => %w[shell powershell meterpreter],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_registry_open_key
              stdapi_registry_check_key_exists
            ]
          }
        }
      )
    )
    register_options([
      OptBool.new('CURRENT', [ true, 'Enumerate currently configured shares', true]),
      OptBool.new('RECENT', [ true, 'Enumerate recently mapped shares', true]),
      OptBool.new('ENTERED', [ true, 'Enumerate recently entered UNC Paths in the Run Dialog', true])
    ])
  end

  # Convert share type ID `val` to readable string
  #
  # @return [String] Share type as readable string
  def share_type(val)
    %w[DISK PRINTER DEVICE IPC SPECIAL TEMPORARY][val] || 'UNKNOWN'
  end

  # Method for enumerating recent mapped drives on target machine
  #
  # @return [Array] List of recently mounted UNC paths
  def enum_recent_mounts(base_key)
    partial_path = base_key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer'
    explorer_keys = registry_enumkeys(partial_path).to_s || ''

    return [] unless explorer_keys.include?('Map Network Drive MRU')

    full_path = "#{partial_path}\\Map Network Drive MRU"
    vals_found = registry_enumvals(full_path)

    return [] unless vals_found

    recent_mounts = []
    registry_enumvals(full_path).each do |k|
      next if k.include?('MRUList')

      mounted_path = registry_getvaldata(full_path, k)
      recent_mounts << mounted_path if mounted_path.starts_with?('\\\\')
    end

    recent_mounts
  end

  # Method for enumerating UNC paths entered in Run dialog box
  #
  # @return [Array] List of MRU historical UNC paths
  def enum_run_unc(base_key)
    full_path = base_key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'
    vals_found = registry_enumvals(full_path)

    return [] unless vals_found

    unc_paths = []
    vals_found.each do |k|
      next if k.include?('MRUList')

      run_entry = registry_getvaldata(full_path, k).to_s
      unc_paths << run_entry.gsub(/\\1$/, '') if run_entry.starts_with?('\\\\')
    end

    unc_paths
  end

  # Method for enumerating configured shares on a target box
  #
  # @return [Array] List of network shares in the form of [ name, type, remark, path ]
  def enum_conf_shares
    shares_key = nil

    [
      'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Shares',
      'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\lanmanserver\\Shares'
    ].each do |k|
      if registry_key_exist?(k)
        shares_key = k
        break
      end
    end

    if shares_key.blank?
      print_status('No network shares were found')
      return
    end

    share_names = registry_enumvals(shares_key)

    if share_names.empty?
      print_status('No network shares were found')
      return
    end

    shares = []
    print_status('The following shares were found:')
    share_names.each do |sname|
      share_info = registry_getvaldata(shares_key, sname)
      next if share_info.nil?

      print_status("\tName: #{sname}")

      stype = remark = path = nil
      share_info.each do |e|
        name, val = e.split('=')
        case name
        when 'Path'
          path = val
          print_status "\tPath: #{path}"
        when 'Type'
          stype = share_type(val.to_i)
          print_status "\tType: #{stype}"
        when 'Remark'
          remark = val
          print_status("\tRemark: #{remark}") unless remark.blank?
        end
      end

      print_status

      # Match the format used by auxiliary/scanner/smb/smb_enumshares
      # with an added field for path
      shares << [ sname, stype, remark, path ]
    end

    report_note(
      host: session,
      type: 'smb.shares',
      data: { shares: shares },
      update: :unique_data
    )
  end

  def run
    unless datastore['CURRENT'] || datastore['RECENT'] || datastore['ENTERED']
      fail_with(Failure::BadConfig, 'At least one option (CURRENT, RECENT, ENTERED) must be enabled. Nothing to do.')
    end

    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    enum_conf_shares if datastore['CURRENT']

    return unless datastore['RECENT'] || datastore['ENTERED']

    mount_history = []
    run_history = []

    if is_system? || is_admin?
      mount_history = enum_recent_mounts('HKEY_CURRENT_USER') if datastore['RECENT']
      run_history = enum_run_unc('HKEY_CURRENT_USER') if datastore['ENTERED']
    else
      keys = registry_enumkeys('HKU') || []
      keys.each do |maybe_sid|
        next unless maybe_sid.starts_with?(SID_PREFIX_USER)
        next if maybe_sid.include?('_Classes')

        mount_history += enum_recent_mounts("HKU\\#{maybe_sid.chomp}") if datastore['RECENT']
        run_history += enum_run_unc("HKU\\#{maybe_sid.chomp}") if datastore['ENTERED']
      end
    end

    unless mount_history.empty?
      print_status('Recent mounts found:')
      mount_history.each do |i|
        print_status("\t#{i}")
      end
      print_status
    end

    unless run_history.empty?
      print_status('Recent UNC paths entered in Run dialog found:')
      run_history.each do |i|
        print_status("\t#{i}")
      end
      print_status
    end
  end
end
