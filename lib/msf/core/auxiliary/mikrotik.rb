# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Mikrotik equipment
  #
  ###
  module Auxiliary::Mikrotik
    include Msf::Auxiliary::Report

    # this handles `export` (default), `export compact`, `export terse` and `export verbose`
    # the format is a header line: `/ tree navigation`
    # followed by commands: `set thing value`
    def export_to_hash(config)
      return {} unless config.is_a? String
      puts 'it was a string'
      config = config.gsub(/\\\s*\n/,'') # replace verbose multiline items as single lines, similar to terse
      output = {}
      header = ''
      puts config.lines.count.to_s
      config.each_line do |line|
        line = line.strip
        # # jul/16/2020 14:26:57 by RouterOS 6.45.9
        # typically the first line in the config
        if %r{^# \w{3}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} by (?<os>\w+) (?<version>[\d\.]+)$} =~ line
          output['OS'] = ["#{os} #{version}"]

        # terse format format is more 'cisco'-ish where header and setting is on one line
        # /interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user
        #/interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out2 password=password user=user
        elsif %r{^(?<section>/[\w -]+)} =~ line && ( line.include?(' add ') || line.include?(' set '))
          [' add ', ' set '].each do |div|
            if line.include?(div)
              line = line.split(div)
              if output[line[0].strip]
                output[line[0].strip] << "#{div}#{line[1]}".strip
                next
              end
              output[line[0].strip] = ["#{div}#{line[1]}".strip]
            end
          end

        # /interface ovpn-client
        # these are the section headers
        elsif %r{^(?<section>/[\w -]+)$} =~ line
          header = section.strip
          output[header] = [] # initialize

        # take any line that isn't commented out
        elsif !line.starts_with?('#') && !header.empty?
          output[header] << line.strip
        end
      end
      output
    end

    # this takes a string of config like 'add connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm'
    # and converts it to a hash of keys and values for easier processing
    def values_to_hash(line)
      return {} unless line.is_a? String
      hash = {}
      array = line.split(' ')
      array.each do |setting|
        key_value = setting.split('=')
        unless key_value.length == 2
          next # skip things like 'add'
        end

        hash[key_value[0].strip] = key_value[1].strip
      end
      hash
    end

    def mikrotik_export_config_eater(thost, tport, config)
      credential_data = {
        address: thost,
        port: tport,
        protocol: 'tcp',
        workspace_id: myworkspace.id,
        origin_type: :service,
        private_type: :password,
        service_name: '',
        module_fullname: fullname,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Default SNMP to UDP
      if tport == 161
        credential_data[:protocol] = 'udp'
      end

      store_loot('mikrotik.config', 'text/plain', thost, config.strip, 'config.txt', 'MikroTik Configuration')

      tuniface = nil

      host_info = {
        host: thost,
        os_name: 'Mikrotik'
      }
      report_host(host_info)
      
      if config.is_a? String
        config = export_to_hash(config)
      end
      config.each do |header, values|
        case header
          #
          # Cover OS details
          #
        when 'OS'
          values.each do |value|
            print_good("#{thost}:#{tport} OS: #{value}")
            v = value.split(' ')
            host_info[:os_name] = v[0]
            host_info[:os_flavor] = v[1]
            report_host(host_info)
          end

          #
          # OpenVPN client details
          #
        when '/interface ovpn-client'
          # https://wiki.mikrotik.com/wiki/Manual:Interface/OVPN#Client_Config
          # add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user
          # add connect-to=10.99.99.98 disabled=yes mac-address=FE:45:B0:31:4A:34 name=ovpn-out3 password=password user=user
          # no such thing as disabled=no, the value is just not there
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} #{value['disabled'] ? 'disabled' : ''} Open VPN Client to #{value['connect-to']} on mac #{value['mac-address']} named #{value['name']} with username #{value['user']} and password #{value['password']}")
            cred = credential_data.dup
            cred[:port] = 1194
            cred[:service_name] = 'openvpn'
            cred[:username] = value['user']
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end

          #
          # PPPoE client details
          #
        when '/interface pppoe-client'
          # https://wiki.mikrotik.com/wiki/Manual:Interface/PPPoE#PPPoE_Client
          # add disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} #{value['disabled'] ? '' : 'disabled'} PPPoE Client on #{value['interface']} named #{value['name']} and service name #{value['service-name']} with username #{value['user']} and password #{value['password']}")
            cred = credential_data.dup
            cred[:username] = value['user']
            cred[:service_name] = 'pppoe'
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end

          #
          # L2TP client details
          #
        when '/interface l2tp-client'
          # https://wiki.mikrotik.com/wiki/Manual:Interface/L2TP#L2TP_Client
          # add connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} #{value['disabled'] ? '' : 'disabled'} L2TP Client to #{value['connect-to']} named #{value['name']} with username #{value['user']} and password #{value['password']}")
            cred = credential_data.dup
            cred[:port] = 1701
            cred[:service_name] = 'l2tp'
            cred[:username] = value['user']
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end
          #
          # PPTP client details
          #
        when '/interface pptp-client'
          # https://wiki.mikrotik.com/wiki/Manual:Interface/PPTP#PPTP_Client
          # add connect-to=10.99.99.99 disabled=no name=pptp-hm password=123 user=pptp-hm
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} #{value['disabled'] ? '':'disabled'} PPTP Client to #{value['connect-to']} named #{value['name']} with username #{value['user']} and password #{value['password']}")
            cred = credential_data.dup
            cred[:service_name] = 'pptp'
            cred[:port] = 1723
            cred[:username] = value['user']
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end
          #
          # SNMP details
          #
        when '/snmp community'
          # https://wiki.mikrotik.com/wiki/Manual:SNMP
          # add addresses=::/0 authentication-password=write name=write write-access=yes
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            if value['encryption-password'] # v3
              print_good("#{thost}:#{tport} SNMP community #{value['name']} with password #{value['authentication-password']}(#{value['authentication-protocol']}), encryption password #{value['encryption-password']}(#{value['encryption-protocol']}) and #{value['write-access'] ? 'write access' : 'read only'}")
            else
              print_good("#{thost}:#{tport} SNMP community #{value['name']} with password #{value['authentication-password']} and #{value['write-access'] ? 'write access' : 'read only'}")
            end

            cred = credential_data.dup
            if value['write-access'] == 'yes'
              cred[:access_level] = 'RW'
            else
              cred[:access_level] = 'RO'
            end
            cred[:protocol] = 'udp'
            cred[:port] = 161
            cred[:service_name] = 'snmp'
            cred[:private_data] = value['name']
            create_credential_and_login(cred)
          end
          #
          # PPP tunnel bridging secret details
          #
        when '/ppp secret'
          # https://wiki.mikrotik.com/wiki/Manual:BCP_bridging_(PPP_tunnel_bridging)#Office_1_configuration
          # add name=ppp1 password=password profile=ppp_bridge
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} #{value['disabled'] ? 'disabled' : ''} PPP tunnel bridging named #{value['name']} with profile name #{value['profile']} and password #{value['password']}")
            cred = credential_data.dup
            cred[:username] = ''
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end

          #
          # hostname details
          #
        when '/system identity'
          # https://wiki.mikrotik.com/wiki/Manual:System/identity#Configuration
          # set name=mikrotik_hostname
          values.each do |value|
            next unless value.starts_with?('set ')

            value = values_to_hash(value)
            host_info[:name] = value['name']
            report_host(host_info)
          end
        end
      end
    end
  end
end
