# -*- coding: binary -*-

require 'metasploit/framework/hashes/identify'

module Msf
  ###
  #
  # This module provides methods for working with Arista equipment
  #
  ###
  module Auxiliary::Arista
    include Msf::Auxiliary::Report

    def arista_eos_config_eater(thost, tport, config)

      if framework.db.active
        credential_data = {
          address: thost,
          port: tport,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :nonreplayable_hash,
          jtr_format: 'sha512,crypt', # default on the devices
          service_name: '',
          module_fullname: fullname,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      end

      # Default SNMP to UDP
      if tport == 161
        credential_data[:protocol] = 'udp'
      end

      store_loot('arista.eos.config', 'text/plain', thost, config.strip, 'config.txt', 'Arista EOS Configuration')

      host_info = {
        host: thost,
        os_name: 'Arista EOS'
      }
      report_host(host_info)

      config.each_line do |line|
        case line

          # one of the first lines
          # ! device: aristaveos (vEOS, EOS-4.19.10M)
          # ! device: switch (DCS-7150S-64-CL, EOS-4.13.2F)
        when /^\s*! device: (.+) \((.+),\s*(.+)-(.+)\)/i
          hostname = Regexp.last_match(1).to_s
          device = Regexp.last_match(2).to_s
          os = Regexp.last_match(3).to_s
          os_ver = Regexp.last_match(4).to_s
          host_info[:os_name] = os
          host_info[:os_flavor] = os_ver
          host_info[:name] = hostname
          report_host(host_info)
          print_good("#{thost}:#{tport} Hostname: #{hostname}, Device: #{device}, OS: #{os}, Version: #{os_ver}")
          # https://www.arista.com/en/um-eos/eos-section-6-1-managing-the-switch-name
          # hostname aristaveos
        when /^\s*hostname (\S+)/i
          host_info[:name] = Regexp.last_match(1).to_s
          report_host(host_info)
          print_good("#{thost}:#{tport} Hostname: #{Regexp.last_match(1)}")
          # https://www.arista.com/en/um-eos/eos-section-4-7-aaa-commands#ww1349127
          # enable secret sha512 $6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1
        when /^\s*enable secret sha512 (.*)$/i
          if framework.db.active
            cred = credential_data.dup
            cred[:username] = 'enable'
            cred[:private_data] = Regexp.last_match(1).to_s
            create_credential_and_login(cred)
          end
          print_good("#{thost}:#{tport} Enable hash: #{Regexp.last_match(1)}")
          # https://www.arista.com/en/um-eos/eos-section-43-3-configuring-snmp?searchword=snmp
          # snmp-server community read ro
          # snmp-server community write rw
        when /^\s*snmp-server community ([^\s]+) (RO|RW)/i
          stype = Regexp.last_match(2).strip
          scomm = Regexp.last_match(1).strip
          print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

          if framework.db.active
            cred = credential_data.dup
            cred[:access_level] = stype.upcase
            cred[:protocol] = 'udp'
            cred[:service_name] = 'snmp'
            cred[:private_type] = :password
            cred[:jtr_format] = ''
            cred[:port] = 161
            cred[:private_data] = scomm
            create_credential_and_login(cred)
          end
          # https://www.arista.com/en/um-eos/eos-section-4-7-aaa-commands#ww1349963
          # username admin privilege 15 role network-admin secret sha512 $6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61
          # username bob privilege 15 secret 5 $1$EGQJlod0$CdkMmW1FoiRgMfbLFD/kB/
          # username rlaney role network-admin secret 0 ralrox
        when /^\s*username ([^\s]+) (?:privilege (\d+) )?(?:role (.+) )?secret (.+) ([^\s]+)/i
          name = Regexp.last_match(1).to_s
          privilege = Regexp.last_match(2).to_s
          role = Regexp.last_match(3).to_s
          # for secret, 0=plaintext, 5=md5sum, sha512=sha512
          secret = Regexp.last_match(4).to_s
          hash = Regexp.last_match(5).to_s
          output = "#{thost}:#{tport} Username '#{name}'"
          unless privilege.empty?
            output << " with privilege #{privilege},"
          end
          unless role.empty?
            output << " Role #{role},"
          end

          if framework.db.active
            cred = credential_data.dup
          else
            cred = {} # throw away, but much less code than constant if statements
          end

          if secret == '0'
            output << " and Password: #{hash}"
            cred[:private_type] = :password
            cred[:jtr_format] = ''
          else
            output << " and Hash: #{hash}"
            cred[:jtr_format] = identify_hash(hash)
          end

          cred[:username] = name
          cred[:private_data] = hash

          if framework.db.active          
            create_credential_and_login(cred)
          end
          print_good(output)
          # aaa root secret sha512 $6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.
        when /^\s*aaa (root) secret (.+) ([^\s]+)/i
          name = Regexp.last_match(1).to_s
          # for secret, 0=plaintext, 5=md5sum, sha512=sha512
          secret = Regexp.last_match(2).to_s
          hash = Regexp.last_match(3).to_s
          output = "#{thost}:#{tport} AAA Username '#{name}'"
          if framework.db.active
            cred = credential_data.dup
          else
            cred = {} # throw away, but much less code than constant if statements
          end

          cred[:username] = name.to_s

          if secret == '0'
            output << " and Password: #{hash}"
            cred[:private_type] = :password
            cred[:jtr_format] = ''
          else
            output << " with Hash: #{hash}"
            cred[:jtr_format] = identify_hash(hash)
          end

          cred[:private_data] = hash.to_s
          if framework.db.active
            create_credential_and_login(cred)
          end
          print_good(output)
        end
      end
    end
  end
end
