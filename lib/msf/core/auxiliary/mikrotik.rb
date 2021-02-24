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

      config = config.gsub(/^\s{2,4}/, '') # replace code indents
      config = config.gsub(/\\\s*\n/, '') # replace verbose multiline items as single lines, similar to terse
      output = {}
      header = ''
      config.each_line do |line|
        line = line.strip
        # # jul/16/2020 14:26:57 by RouterOS 6.45.9
        # typically the first line in the config
        if %r{^# \w{3}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} by (?<os>\w+) (?<version>[\d\.]+)$} =~ line
          output['OS'] = ["#{os} #{version}"]

        # terse format format is more 'cisco'-ish where header and setting is on one line
        # /interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user
        # /interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out2 password=password user=user
        elsif %r{^(?<section>/[\w -]+)} =~ line && (line.include?(' add ') || line.include?(' set '))
          [' add ', ' set '].each do |div|
            next unless line.include?(div)

            line = line.split(div)
            if output[line[0].strip]
              output[line[0].strip] << "#{div}#{line[1]}".strip
              next
            end
            output[line[0].strip] = ["#{div}#{line[1]}".strip]
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
        # verbose mode gives empty fields, however our processing makes them "" instead of empty
        # so we check if its empty and skip it to prevent a double quote or escaped double quote
        # field from being loaded
        next if key_value[1].strip == '""' || key_value[1].strip == '\\"\\"'

        hash[key_value[0].strip] = key_value[1].strip
      end
      hash
    end

    def mikrotik_swos_config_eater(thost, tport, config)
      if framework.db.active
        credential_data = {
          address: thost,
          port: tport,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :password,
          service_name: '',
          module_fullname: fullname,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      end

      # Default SNMP to UDP
      if tport == 161
        credential_data[:protocol] = 'udp'
      end

      store_loot('mikrotik.config', 'text/plain', thost, config.strip, 'config.txt', 'MikroTik Configuration')

      host_info = {
        host: thost,
        os_name: 'SwOS'
      }
      report_host(host_info)

      # Unfortunately SWoS doesn't have a very easily parsable format.  Config is exported in one big string
      # they follow a key:value format followed by a comma, but since values can be arrays,
      # or hashes the actual parsing of such would be pretty difficult.  Since there isn't a ton of value
      # in this file, we simply run some regexes against it

      # ,sys.b:{id:'4d696b726f54696b2d637373333236',wdt:0x01,dsc:0x01,ivl:0x00,alla:0x00,allm:0x00,allp:0x03ffffff,avln:0x00,prio:0x8000,cost:0x00,igmp:0x00,ip:0x0158a8c0,iptp:0x02,dtrp:0x03ffffff,ainf:0x01}
      # part we care about: ,ip:0x0158a8c0
      if /,ip:0x(?<ip>[\da-f]+)/ =~ config
        ip = ip.scan(/../).map { |x| x.hex.to_i }.reverse.join('.')
        print_status("#{thost}:#{tport} IP Address: #{ip}")
      end

      # ,sys.b:{id:'4d696b726f54696b2d637373333236'
      if /,sys.b:{id:'(?<host>[a-f\d]*)'/ =~ config
        host = Array(host).pack('H*')
        host_info[:name] = host
        report_host(host_info)
        print_good("#{thost}:#{tport} Hostname: #{host}")
      end

      # pull the switch password .pwd.b:{pwd:'61646d696e'} -> admin
      # pull the switch password .pwd.b:{pwd:''} -> (blank, which is default)
      if /,\.pwd\.b:{pwd:'(?<password>[a-f\d]*)'}/ =~ config
        password = Array(password).pack('H*')
        print_good("#{thost}:#{tport} Admin login password: #{password}")
        if framework.db.active
          cred = credential_data.dup
          cred[:port] = 80
          cred[:protocol] = 'tcp'
          cred[:service_name] = 'www'
          cred[:username] = 'admin' # hardcoded
          cred[:private_data] = password.to_s
          create_credential_and_login(cred)
        end
      end

      # ,snmp.b:{en:0x01,com:'7075626c6963',ci:'636f6e74616374696e666f',loc:'6c6f636174696f6e'}
      # ,snmp.b:{en:0x01,com:'7075626c6963',ci:'',loc:''}
      if /,snmp\.b:{en:0x01,com:'(?<community>[a-f\d]*)',ci:'(?<contact>[a-f\d]*)',loc:'(?<location>[a-f\d]*)'}/ =~ config
        community = Array(community).pack('H*')
        contact = Array(contact).pack('H*')
        location = Array(location).pack('H*')
        print_good("#{thost}:#{tport} SNMP Community: #{community}, contact: #{contact}, location: #{location}")
        if framework.db.active
          cred = credential_data.dup
          cred[:port] = 161
          cred[:protocol] = 'udp'
          cred[:service_name] = 'snmp'
          cred[:private_data] = community.to_s
          create_credential_and_login(cred)
        end
      end

      # ,nm:['506f727431','506f727432','506f727433','506f727434','506f727435','506f727436','506f727437','506f727438','506f727439','506f72743130','506f72743131','506f72743132','506f72743133','506f72743134','506f72743135','506f72743136','506f72743137','506f72743138','506f72743139','506f72743230','506f72743231','506f72743232','506f72743233','75706c696e6b','53465031','53465032']}
      if /,nm:\[(?<interfaces>[a-f\d',]*)\]/ =~ config
        interfaces = interfaces.split(',')
        interfaces.each_with_index do |iface, i|
          iface = iface.gsub("'", '')
          iface = Array(iface).pack('H*')
          next if iface == "Port#{i + 1}" || /SFP\d/ =~ iface # skip defaults

          print_status("#{thost}:#{tport} Port #{i + 1} Named: #{iface}")
        end
      end

    end

    def mikrotik_routeros_config_eater(thost, tport, config)
      if framework.db.active
        credential_data = {
          address: thost,
          port: tport,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :password,
          service_name: '',
          module_fullname: fullname,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      end

      # Default SNMP to UDP
      if tport == 161
        credential_data[:protocol] = 'udp'
      end

      store_loot('mikrotik.config', 'text/plain', thost, config.strip, 'config.txt', 'MikroTik Configuration')

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
            next unless framework.db.active

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
            next unless framework.db.active

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
            next unless framework.db.active

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
            print_good("#{thost}:#{tport} #{value['disabled'] ? '' : 'disabled'} PPTP Client to #{value['connect-to']} named #{value['name']} with username #{value['user']} and password #{value['password']}")
            next unless framework.db.active

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

            next unless framework.db.active

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
            next unless framework.db.active

            cred = credential_data.dup
            cred[:username] = ''
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end
          #
          # SMB users details
          #
        when '/ip smb users'
          # https://wiki.mikrotik.com/wiki/Manual:IP/SMB#User_setup
          # add name=mtuser password=mtpasswd read-only=no
          # add disabled=yes name=disableduser password=disabledpasswd
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} #{value['disabled'] == 'yes' ? 'disabled' : ''} SMB Username #{value['name']} and password #{value['password']}#{' with RO only access' if value['read-only'] == 'yes' || !value['read-only']}")
            next unless framework.db.active

            cred = credential_data.dup
            if value['read-only'] == 'yes' || !value['read-only']
              cred[:access_level] = 'RO'
            end
            cred[:service_name] = 'smb'
            cred[:username] = value['name']
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end
          #
          # SMTP user details
          #
        when '/tool e-mail'
          # https://wiki.mikrotik.com/wiki/Manual:Tools/email#Properties
          # set address=1.1.1.1 from=router@router.com password=smtppassword user=smtpuser
          values.each do |value|
            next unless value.starts_with?('set ')

            value = values_to_hash(value)
            print_good("#{thost}:#{tport} SMTP Username #{value['user']} and password #{value['password']} for #{value['address']}:#{value['port'] || '25'}")
            next unless framework.db.active

            cred = credential_data.dup
            cred[:service_name] = 'smtp'
            cred[:port] = value['port'] ? value['port'].to_i : 25
            cred[:address] = value['address']
            cred[:protocol] = 'tcp'
            cred[:username] = value['user']
            cred[:private_data] = value['password']
            create_credential_and_login(cred)
          end
          #
          # Wireless networks details
          #
        when '/interface wireless security-profiles'
          # https://wiki.mikrotik.com/wiki/Manual:Interface/Wireless#Security_Profiles
          # add name=openwifi supplicant-identity=MikroTik
          # add authentication-types=wpa-psk mode=dynamic-keys name=wpawifi supplicant-identity=MikroTik wpa-pre-shared-key=presharedkey
          # add authentication-types=wpa2-psk mode=dynamic-keys name=wpa2wifi supplicant-identity=MikroTik wpa2-pre-shared-key=presharedkey
          # add authentication-types=wpa2-eap mode=dynamic-keys mschapv2-password=password mschapv2-username=username name=wpaeapwifi supplicant-identity=MikroTik
          # add mode=static-keys-required name=wepwifi static-key-0=0123456789 static-key-1=0987654321 static-key-2=1234509876 static-key-3=0192837645 supplicant-identity=MikroTik
          values.each do |value|
            next unless value.starts_with?('add ')

            value = values_to_hash(value)
            output = "#{thost}:#{tport} Wireless AP #{value['name']}"

            if !value['authentication-types'] && (!value['mode'] || value['mode'] == 'none') # open wifi
              output << ' with no encryption (open wifi)'
              vprint_good(output)
              next
            end

            if framework.db.active
              cred = credential_data.dup
            else
              cred = {}
            end

            # The following section is a little complicated due to the way mikrotik exports values
            # in compact/terse/default mode, it will skip printing default values, so we have to check
            # that keys are present.
            # In verbose mode, they will print but be empty
            if value['wpa-pre-shared-key'] && !value['wpa-pre-shared-key'].empty?
              output << " with WPA password #{value['wpa-pre-shared-key']}"
              if framework.db.active
                cred[:private_data] = value['wpa-pre-shared-key']
                create_credential_and_login(cred)
              end
            elsif value['wpa2-pre-shared-key'] && !value['wpa2-pre-shared-key'].empty?
              output << " with WPA2 password #{value['wpa2-pre-shared-key']}"
              if framework.db.active
                cred[:private_data] = value['wpa2-pre-shared-key']
                create_credential_and_login(cred)
              end
            elsif value['authentication-types'] == 'wpa2-eap'
              output << " with WPA2-EAP username #{value['mschapv2-username']} password #{value['mschapv2-password']}"
              if framework.db.active
                cred[:username] = value['mschapv2-username']
                cred[:private_data] = value['mschapv2-password']
                create_credential_and_login(cred)
              end
            elsif value['static-key-0'] || value['static-key-1'] || value['static-key-2'] || value['static-key-3']
              (0..3).each do |i|
                key = "static-key-#{i}"
                next unless value[key]

                output << " with WEP password #{value[key]}"
                if framework.db.active
                  cred[:private_data] = value[key]
                  create_credential_and_login(cred) # run for each key we find
                end
              end
            end

            print_good(output)
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
