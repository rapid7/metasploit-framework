##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    require 'resolv'
    include Msf::Exploit::Remote::DNS::Enumeration

    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Azure Subdomain Scanner and Enumerator',
          'Description' => 'This module can be used for enumerating public Azure services by locating valid subdomains through various DNS queries.',
          'Author' => ['RoseSecurity <RoseSecurityConsulting[at]protonmail.me>'],
          'License' => MSF_LICENSE,
        )
      )
    register_options(
        [
          OptString.new('DOMAIN', [true, 'The target domain without TLD (Ex: victim rather than victim.org)']),
          OptBool.new('PERMUTATIONS', [false, 'Prepend and append permutated keywords to domain (This option can take minutes to complete)', false]),
          OptBool.new('ENUM_A', [true, 'Enumerate DNS A record', true]),
          OptBool.new('ENUM_CNAME', [true, 'Enumerate DNS CNAME record', true]),
          OptBool.new('ENUM_MX', [true, 'Enumerate DNS MX record', true]),
          OptBool.new('ENUM_NS', [true, 'Enumerate DNS NS record', true]),
          OptBool.new('ENUM_SOA', [true, 'Enumerate DNS SOA record', true]),
          OptBool.new('ENUM_TXT', [true, 'Enumerate DNS TXT record', true]),
        ])
    end

    def run
      # Array of subdomains to enumerate
      domain = datastore['DOMAIN']
      subdomains = [ ".onmicrosoft.com",
          ".scm.azurewebsites.net",
          ".azurewebsites.net",
          ".p.azurewebsites.net",
          ".cloudapp.net",
          ".file.core.windows.net",
          ".blob.core.windows.net",
          ".queue.core.windows.net",
          ".table.core.windows.net",
          ".mail.protection.outlook.com",
          ".sharepoint.com",
          ".redis.cache.windows.net",
          ".documents.azure.com",
          ".database.windows.net",
          ".vault.azure.net",
          ".azureedge.net",
          ".search.windows.net",
          ".azure-api.net",
          ".azurecr.io", ]

      # Array of keywords to prepend and append
      permutations = [ "root",
          "web",
          "api",
          "azure",
          "azure-logs",
          "data",
          "database",
          "data-private",
          "data-public",
          "dev",
          "development",
          "demo",
          "files",
          "filestorage",
          "internal",
          "keys",
          "logs",
          "private",
          "prod",
          "production",
          "public",
          "service",
          "services",
          "splunk",
          "sql",
          "staging",
          "storage",
          "storageaccount",
          "test",
          "useast",
          "useast2",
          "centralus",
          "northcentralus",
          "westcentralus",
          "westus",
          "westus2", ]

      # Create permutated array of keywords and target domain
      if datastore['PERMUTATIONS']
        permutated_domains = Array.new()
        for keywords in permutations do
            permutated_domains.append(domain + "-" + keywords)
            permutated_domains.append(keywords + "-" + domain)
        end

        # Normal list of subdomains
        target_domains = Array.new()
        for tld in subdomains do
          target_domains.append(domain + tld)
        end

        # Permutated list of subdomains
        for tld in subdomains do
            for domain in permutated_domains do
                target_domains.append(domain + tld)
            end
        end

        # Query DNS records of permutated and normal target subdomains
        for domain in target_domains do
          begin
            if Resolv.getaddress domain
              print_status("\nDiscovered Target Domain: #{domain} \n")
              dns_get_a(domain) if datastore['ENUM_A']
              dns_get_cname(domain) if datastore['ENUM_CNAME']
              dns_get_ns(domain) if datastore['ENUM_NS']
              dns_get_mx(domain) if datastore['ENUM_MX']
              dns_get_soa(domain) if datastore['ENUM_SOA']
              dns_get_txt(domain) if datastore['ENUM_TXT']
            end
            rescue
              next
            end
          end
      else

        # Query DNS records of normal target subdomains
        target_domains = Array.new()
        for tld in subdomains do
            target_domains.append(domain + tld)
        end
        for domain in target_domains do
          begin
            if Resolv.getaddress domain
              print_status("\nDiscovered Target Domain: #{domain} \n")
              dns_get_a(domain) if datastore['ENUM_A']
              dns_get_cname(domain) if datastore['ENUM_CNAME']
              dns_get_ns(domain) if datastore['ENUM_NS']
              dns_get_mx(domain) if datastore['ENUM_MX']
              dns_get_soa(domain) if datastore['ENUM_SOA']
              dns_get_txt(domain) if datastore['ENUM_TXT']
            end
            rescue
              next
            end
          end
        end
      end
    end
