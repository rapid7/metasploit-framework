# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Prometheus node exporter
  #
  ###
  module Auxiliary::Prometheus
    include Msf::Auxiliary::Report

    # returns username, password
    def process_authorization(auth)
      if auth['credentials']
        # credential foobar
        return '', auth['credentials']
      elsif auth['credentials_file']
        # type: Bearer
        # credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        return auth['type'], auth['credentials_file']
      end
    end

    def prometheus_config_eater(yamlconf)
      table_creds = Rex::Text::Table.new(
        'Header' => 'Credentials',
        'Indent' => 2,
        'Columns' =>
        [
          'Name',
          'Config',
          'Host',
          'Port',
          'Public/Username',
          'Private/Password/Token',
          'Notes'
        ]
      )

      credential_data = {
        # these 4 need to be changed every time
        # address: thost,
        # port: tport,
        # username: username
        # private_data: hash
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        origin_type: :service,
        private_type: :password,
        service_name: '',
        module_fullname: fullname,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      yamlconf['scrape_configs']&.each do |scrape|
        # check for targets which have creds built in to the URL
        if scrape['static_configs']
          scrape['static_configs']&.each do |static|
            static['targets']&.each do |target|
              if target.include? '@'
                uri = URI(target)
                cred2 = credential_data.dup
                cred2[:port] = uri.port
                cred2[:address] = uri.host
                cred2[:username] = uri.user
                cred2[:private_data] = uri.password
                cred2[:service_name] = uri.scheme
                create_credential_and_login(cred2)
                table_creds << [
                  scrape['job_name'],
                  'static_configs Target',
                  uri.host,
                  uri.port,
                  uri.user,
                  uri.password,
                  ''
                ]
              end
            end
          end
        elsif scrape['dns_sd_configs']
          scrape['dns_sd_configs']&.each do |dns_sd_configs|
            dns_sd_configs['names']&.each do |name|
              password = scrape.dig('basic_auth', 'password')
              password = scrape.dig('basic_auth', 'password_file') if scrape.dig('basic_auth', 'password_file')
              uri = URI("#{scrape['scheme']}://#{name}")
              cred2 = credential_data.dup
              cred2[:port] = uri.port
              cred2[:address] = uri.host
              cred2[:username] = scrape.dig('basic_auth', 'username')
              cred2[:private_data] = password
              cred2[:service_name] = scrape['scheme']
              create_credential_and_login(cred2)
              table_creds << [
                scrape['job_name'],
                'dns_sd_configs',
                uri.host,
                uri.port,
                scrape.dig('basic_auth', 'username'),
                password,
                ''
              ]
            end
          end
        elsif scrape['consul_sd_configs']
          scrape['consul_sd_configs']&.each do |consul_sd_configs|
            uri = URI("#{consul_sd_configs['scheme']}://#{consul_sd_configs['server']}")
            cred2 = credential_data.dup
            cred2[:port] = uri.port
            cred2[:address] = uri.host
            cred2[:username] = ''
            cred2[:private_data] = consul_sd_configs['token']
            cred2[:service_name] = consul_sd_configs['scheme']
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'consul_sd_configs',
              uri.host,
              uri.port,
              '',
              consul_sd_configs['token'],
              "Path Prefix: #{consul_sd_configs['path_prefix']}"
            ]
          end
        elsif scrape['authorization']
          username, password = process_authorization(scrape['authorization'])
          cred2 = credential_data.dup
          cred2[:port] = ''
          cred2[:address] = ''
          cred2[:username] = username
          cred2[:private_data] = password
          create_credential_and_login(cred2)
          table_creds << [
            scrape['job_name'],
            'authorization',
            '',
            '',
            username,
            password,
            ''
          ]
        elsif scrape['kubernetes_sd_configs']
          # sometimes set per config
          scrape['kubernetes_sd_configs']&.each do |kubernetes_sd_configs|
            next unless kubernetes_sd_configs['api_server']

            username = kubernetes_sd_configs.dig('basic_auth', 'username')
            password = kubernetes_sd_configs.dig('basic_auth', 'password')
            password = kubernetes_sd_configs.dig('basic_auth', 'password_file') if kubernetes_sd_configs.dig('basic_auth', 'password_file')
            # sometimes set for all kubernetes_sd_configs, not in the individual array
            if scrape['basic_auth']
              username = scrape.dig('basic_auth', 'username')
              password = scrape.dig('basic_auth', 'password')
              password = scrape.dig('basic_auth', 'password_file') if scrape.dig('basic_auth', 'password_file')
            end

            uri = URI(kubernetes_sd_configs['api_server'])
            cred2 = credential_data.dup
            cred2[:port] = uri.port
            cred2[:address] = uri.host
            cred2[:username] = username
            cred2[:private_data] = password
            cred2[:service_name] = uri.scheme
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'kubernetes_sd_configs',
              uri.host,
              uri.port,
              username,
              password,
              "Role: #{kubernetes_sd_configs['role']}"
            ]
          end
        elsif scrape['kuma_sd_configs']
          scrape['kuma_sd_configs']&.each do |targets|
            if targets['server'].include? '@'
              uri = URI(targets['server'])
              cred2 = credential_data.dup
              cred2[:port] = uri.port
              cred2[:address] = uri.host
              cred2[:username] = uri.user
              cred2[:private_data] = uri.password
              cred2[:service_name] = uri.scheme
              create_credential_and_login(cred2)
              table_creds << [
                scrape['job_name'],
                'kuma_sd_configs',
                uri.host,
                uri.port,
                uri.user,
                uri.password,
                ''
              ]
            end
          end
        elsif scrape['marathon_sd_configs']
          scrape['marathon_sd_configs']&.each do |marathon_sd_configs|
            marathon_sd_configs['servers']&.each do |servers|
              uri = URI(servers)
              cred2 = credential_data.dup
              cred2[:port] = uri.port
              cred2[:address] = uri.host
              cred2[:username] = ''
              cred2[:private_data] = marathon_sd_configs['auth_token']
              cred2[:service_name] = uri.scheme
              create_credential_and_login(cred2)
              table_creds << [
                scrape['job_name'],
                'marathon_sd_configs',
                uri.host,
                uri.port,
                '',
                marathon_sd_configs['auth_token'],
                ''
              ]
            end
          end
        elsif scrape['nomad_sd_configs']
          scrape['nomad_sd_configs']&.each do |targets|
            if targets['server'].include? '@'
              uri = URI(targets['server'])
              cred2 = credential_data.dup
              cred2[:port] = uri.port
              cred2[:address] = uri.host
              cred2[:username] = uri.user
              cred2[:private_data] = uri.password
              cred2[:service_name] = uri.scheme
              create_credential_and_login(cred2)
              table_creds << [
                scrape['job_name'],
                'nomad_sd_configs',
                uri.host,
                uri.port,
                uri.user,
                uri.password,
                ''
              ]
            end
          end
        elsif scrape['ec2_sd_configs']
          scrape['ec2_sd_configs']&.each do |ec2_sd_configs|
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = ec2_sd_configs['access_key']
            cred2[:private_data] = ec2_sd_configs['secret_key']
            cred2[:service_name] = ''
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'ec2_sd_configs',
              '',
              '',
              ec2_sd_configs['access_key'],
              ec2_sd_configs['secret_key'],
              "Region: #{ec2_sd_configs['region']}, Profile: #{ec2_sd_configs['profile']}"
            ]
          end
        elsif scrape['lightsail_sd_configs']
          scrape['lightsail_sd_configs']&.each do |lightsail_sd_configs|
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = lightsail_sd_configs['access_key']
            cred2[:private_data] = lightsail_sd_configs['secret_key']
            cred2[:service_name] = ''
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'lightsail_sd_configs',
              '',
              '',
              lightsail_sd_configs['access_key'],
              lightsail_sd_configs['secret_key'],
              "Region: #{lightsail_sd_configs['region']}, Profile: #{lightsail_sd_configs['profile']}"
            ]
          end
        elsif scrape['azure_sd_configs']
          scrape['azure_sd_configs']&.each do |azure_sd_configs|
            cred2 = credential_data.dup
            cred2[:port] = azure_sd_configs['port']
            cred2[:address] = ''
            cred2[:username] = azure_sd_configs['client_id']
            cred2[:private_data] = azure_sd_configs['client_secret']
            cred2[:service_name] = azure_sd_configs['authentication_method']
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'azure_sd_configs',
              '',
              azure_sd_configs['port'],
              azure_sd_configs['client_id'],
              azure_sd_configs['client_secret'],
              "Environment: #{azure_sd_configs['environment']}, Subscription ID: #{azure_sd_configs['subscription_id']}, Resource Group: #{azure_sd_configs['resource_group']}, Tenant ID: #{azure_sd_configs['tenant_id']}"
            ]
          end
        elsif scrape['http_sd_configs']
          scrape['http_sd_configs']&.each do |http_sd_configs|
            if http_sd_configs['url'].include? '@'
              uri = URI(http_sd_configs['url'])
              cred2 = credential_data.dup
              cred2[:port] = uri.port
              cred2[:address] = uri.host
              cred2[:username] = uri.user
              cred2[:private_data] = uri.password
              cred2[:service_name] = uri.scheme
              create_credential_and_login(cred2)
              table_creds << [
                scrape['job_name'],
                'http_sd_configs',
                uri.host,
                uri.port,
                uri.user,
                uri.password,
                ''
              ]
            end
          end
        elsif scrape['digitalocean_sd_configs']
          scrape['digitalocean_sd_configs']&.each do |digitalocean_sd_configs|
            username, password = process_authorization(digitalocean_sd_configs['authorization'])
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = username
            cred2[:private_data] = password
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'digitalocean_sd_configs',
              '',
              '',
              username,
              password,
              ''
            ]
          end
        elsif scrape['hetzner_sd_configs']
          scrape['hetzner_sd_configs']&.each do |hetzner_sd_configs|
            username = hetzner_sd_configs.dig('basic_auth', 'username')
            password = hetzner_sd_configs.dig('basic_auth', 'password')

            username, password = process_authorization(hetzner_sd_configs['authorization']) if hetzner_sd_configs.dig('authorization', 'credentials')

            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = username
            cred2[:private_data] = password
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'hetzner_sd_configs',
              '',
              '',
              username,
              password,
              hetzner_sd_configs['role']
            ]
          end
        elsif scrape['eureka_sd_configs']
          scrape['eureka_sd_configs']&.each do |eureka_sd_configs|
            if eureka_sd_configs['server'].include? '@'
              uri = URI(eureka_sd_configs['server'])
              cred2 = credential_data.dup
              cred2[:port] = uri.port
              cred2[:address] = uri.host
              cred2[:username] = uri.user
              cred2[:private_data] = uri.password
              cred2[:service_name] = uri.scheme
              create_credential_and_login(cred2)
              table_creds << [
                scrape['job_name'],
                'eureka_sd_configs',
                uri.host,
                uri.port,
                uri.user,
                uri.password,
                ''
              ]
            end
          end
        elsif scrape['ovhcloud_sd_configs']
          scrape['ovhcloud_sd_configs']&.each do |ovhcloud_sd_configs|
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ovhcloud_sd_configs['endpoint']
            cred2[:username] = ovhcloud_sd_configs['application_key']
            cred2[:private_data] = ovhcloud_sd_configs['application_secret']
            cred2[:service_name] = ovhcloud_sd_configs['service']
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'ovhcloud_sd_configs',
              ovhcloud_sd_configs['endpoint'],
              '',
              ovhcloud_sd_configs['application_key'],
              ovhcloud_sd_configs['application_secret'],
              "Consumer Key: #{ovhcloud_sd_configs['consumer_key']}, Service: #{ovhcloud_sd_configs['service']}"
            ]
          end
        elsif scrape['scaleway_sd_configs']
          scrape['scaleway_sd_configs']&.each do |scaleway_sd_configs|
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = scaleway_sd_configs['access_key']
            cred2[:private_data] = scaleway_sd_configs['secret_key']
            cred2[:service_name] = scaleway_sd_configs['role']
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'scaleway_sd_configs',
              '',
              '',
              scaleway_sd_configs['access_key'],
              scaleway_sd_configs['secret_key'],
              "Project ID: #{scaleway_sd_configs['project_id']}, Role: #{scaleway_sd_configs['role']}"
            ]
          end
        elsif scrape['linode_sd_configs']
          scrape['linode_sd_configs']&.each do |linode_sd_configs|
            username, password = process_authorization(linode_sd_configs['authorization'])
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = username
            cred2[:private_data] = password
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'linode_sd_configs',
              '',
              '',
              username,
              password,
              ''
            ]
          end
        elsif scrape['uyuni_sd_configs']
          scrape['uyuni_sd_configs']&.each do |uyuni_sd_configs|
            uri = URI(uyuni_sd_configs['server'])
            cred2 = credential_data.dup
            cred2[:port] = uri.port
            cred2[:address] = uri.host
            cred2[:username] = uyuni_sd_configs['username']
            cred2[:private_data] = uyuni_sd_configs['password']
            cred2[:service_name] = uri.scheme
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'uyuni_sd_configs',
              uri.host,
              uri.port,
              uyuni_sd_configs['username'],
              uyuni_sd_configs['password'],
              ''
            ]
          end
        elsif scrape['ionos_sd_configs']
          scrape['ionos_sd_configs']&.each do |ionos_sd_configs|
            username, password = process_authorization(ionos_sd_configs['authorization'])
            # we may hit an issue here where we have a type stored in username, but use datacenter_id
            # as the username
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = ionos_sd_configs['datacenter_id']
            cred2[:private_data] = password
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'ionos_sd_configs',
              '',
              '',
              ionos_sd_configs['datacenter_id'],
              password,
              ''
            ]
          end
        elsif scrape['vultr_sd_configs']
          scrape['vultr_sd_configs']&.each do |vultr_sd_configs|
            username, password = process_authorization(vultr_sd_configs['authorization'])
            cred2 = credential_data.dup
            cred2[:port] = ''
            cred2[:address] = ''
            cred2[:username] = username
            cred2[:private_data] = password
            create_credential_and_login(cred2)
            table_creds << [
              scrape['job_name'],
              'vultr_sd_configs',
              '',
              '',
              username,
              password,
              ''
            ]
          end
        end
      end
      print_good(table_creds.to_s) if !table_creds.rows.empty?
    end

    def process_results_page(page)
      # data is in a strange 'label{optional_kv_hash-ish} value' format.
      return nil if page.nil?

      results = []
      page.scan(/^(?<name>\w+)(?:{(?<labels>[^}]+)})? (?<value>[\w.+-]+)/).each do |hit|
        result = {}
        value = { 'value' => hit[2], 'labels' => {} }
        if hit[1]
          hit[1].scan(/(?<key>[^=]+?)="(?<value>[^"]*)",?/).each do |label|
            value['labels'][label[0]] = label[1]
          end
        end
        result[hit[0]] = value
        results.append(result)
      end
      return results
    end
  end
end
