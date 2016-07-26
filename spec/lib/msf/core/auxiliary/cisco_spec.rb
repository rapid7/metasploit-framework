# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/cisco'

RSpec.describe Msf::Auxiliary::Cisco do
  class DummyClass
    include Msf::Auxiliary::Cisco
    def framework
      Msf::Simple::Framework.create(
          'ConfigDirectory' => Rails.root.join('spec', 'dummy', 'framework', 'config').to_s,
          # don't load any module paths so we can just load the module under test and save time
          'DeferModuleLoads' => true
      )
    end
    def print_good(str=nil)
      raise StandardError("This method needs to be stubbed.")
    end
    def store_cred(hsh=nil)
      raise StandardError("This method needs to be stubbed.")
    end
  end
  
  subject(:aux_cisco) { DummyClass.new }
  
  context '#cisco_ios_config_eater' do
    
    it 'deals with udp ports' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:161 Unencrypted Enable Password: 1511021F0725')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "enable password 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 161,
          user: "",
          pass: "1511021F0725",
          type: "password",
          collect_type: "password",
          active: true,
          proto: 'udp'
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',161,'enable password 1511021F0725')
    end
    
    context 'Enable Password|Secret' do
      
      it 'with password type 0' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Enable Password: password0')
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.enable_pass", "text/plain", "127.0.0.1", "password0", "enable_password.txt", "Cisco IOS Enable Password"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "enable password 0 password0", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            :host=>"127.0.0.1",
            :port=>1337,
            :user=>"",
            :pass=>"password0",
            :type=>"password",
            :collect_type=>"password",
            :active=>true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'enable password 0 password0')
      end
      
      it 'with password type 5' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 MD5 Encrypted Enable Password: somehashlikestring')
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'enable password 5 somehashlikestring')
      end
      
      it 'with password type 7' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Decrypted Enable Password: cisco')
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.enable_pass", "text/plain", "127.0.0.1", "cisco", "enable_password.txt", "Cisco IOS Enable Password"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "enable password 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            :host=>"127.0.0.1",
            :port=>1337,
            :user=>"",
            :pass=>"cisco",
            :type=>"password",
            :collect_type=>"password",
            :active=>true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'enable password 7 1511021F0725')
      end
      
    end
    
    it 'enable password' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Unencrypted Enable Password: 1511021F0725')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "enable password 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "1511021F0725",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'enable password 1511021F0725')
    end
    
    context 'snmp-server community' do
      
      it 'with RO' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 SNMP Community (RO): 1511021F0725')
        expect(aux_cisco).to receive(:store_cred).with(
          {
            :host=>"127.0.0.1",
            :port=>161,
            :user=>"",
            :pass=>"1511021F0725",
            :type=>"password_ro",
            :collect_type=>"password_ro",
            :sname=>"snmp",
            :proto=>"udp",
            :active=>true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'snmp-server community 1511021F0725 RO')
      end
      
      it 'with RW' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 SNMP Community (RW): 1511021F0725')
        expect(aux_cisco).to receive(:store_cred).with(
          {
            :host=>"127.0.0.1",
            :port=>161,
            :user=>"",
            :pass=>"1511021F0725",
            :type=>"password",
            :collect_type=>"password",
            :sname=>"snmp",
            :proto=>"udp",
            :active=>true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'snmp-server community 1511021F0725 RW')
      end
      
    end
    
    it 'password 7' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Decrypted VTY Password: cisco')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "password 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "cisco",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'password 7 1511021F0725')
    end
    
    it 'password|secret 5' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 MD5 Encrypted VTY Password: password')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.vty_password", "text/plain", "127.0.0.1", "password", "vty_password_hash.txt", "Cisco IOS VTY Password Hash (MD5)"
      )
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "password 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'password 5 1511021F0725')
    end
    
    it 'password 0' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Unencrypted VTY Password: 1511021F0725')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "password 0 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "1511021F0725",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'password 0 1511021F0725')
    end
    
    it 'password' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Unencrypted VTY Password: 1511021F0725')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "password 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "1511021F0725",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'password 1511021F0725')
    end
    
    it 'encryption key' do
      expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Wireless WEP Key: 1511021F0725')
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "encryption key 777 size 8bit 8 1511021F0725", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.wireless_wep", "text/plain", "127.0.0.1", "1511021F0725", "wireless_wep.txt", "Cisco IOS Wireless WEP Key"
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'encryption key 777 size 8bit 8 1511021F0725')
    end
    
    context 'wpa-psk' do
      it 'with password type 0' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Wireless WPA-PSK Password: 1511021F0725')
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "wpa-psk ascii 0 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.wireless_wpapsk", "text/plain", "127.0.0.1", "1511021F0725", "wireless_wpapsk.txt", "Cisco IOS Wireless WPA-PSK Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "",
            pass: "1511021F0725",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'wpa-psk ascii 0 1511021F0725')
      end
      
      it 'with password type 5' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Wireless WPA-PSK MD5 Password Hash: 1511021F0725')
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "wpa-psk ascii 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.wireless_wpapsk_hash", "text/plain", "127.0.0.1", "1511021F0725", "wireless_wpapsk_hash.txt", "Cisco IOS Wireless WPA-PSK Password Hash (MD5)"
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'wpa-psk ascii 5 1511021F0725')
      end
      
      it 'with password type 7' do
        expect(aux_cisco).to receive(:print_good).with('127.0.0.1:1337 Wireless WPA-PSK Decrypted Password: cisco')
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "wpa-psk ascii 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.wireless_wpapsk", "text/plain", "127.0.0.1", "cisco", "wireless_wpapsk.txt", "Cisco IOS Wireless WPA-PSK Decrypted Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "",
            pass: "cisco",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'wpa-psk ascii 7 1511021F0725')
      end
            
    end
    
    it 'crypto isakmp key' do
      expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 VPN IPSEC ISAKMP Key 'somestring' Host 'someaddress'")
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1",  "crypto isakmp key somestring address someaddress", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.vpn_ipsec_key", "text/plain", "127.0.0.1", "somestring", "vpn_ipsec_key.txt", "Cisco VPN IPSEC Key"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "somestring",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'crypto isakmp key somestring address someaddress')
    end
    
    it 'interface tunnel' do
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1",  "interface tunnel7", "config.txt", "Cisco IOS Configuration"
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'interface tunnel7')
    end
    
    it 'tunnel key' do
      expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 GRE Tunnel Key somestring for Interface Tunnel ")
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.gre_tunnel_key", "text/plain", "127.0.0.1", "tunnel_somestring", "gre_tunnel_key.txt", "Cisco GRE Tunnel Key"
      )
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1",  "tunnel key somestring", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "somestring",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'tunnel key somestring')
    end
    
    it 'ip nhrp authentication' do
      expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 NHRP Authentication Key somestring for Interface Tunnel ")
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.config", "text/plain", "127.0.0.1", "ip nhrp authentication somestring", "config.txt", "Cisco IOS Configuration"
      )
      expect(aux_cisco).to receive(:store_loot).with(
        "cisco.ios.nhrp_tunnel_key", "text/plain", "127.0.0.1", "tunnel_somestring", "nhrp_tunnel_key.txt", "Cisco NHRP Authentication Key"
      )
      expect(aux_cisco).to receive(:store_cred).with(
        {
          host: "127.0.0.1",
          port: 1337,
          user: "",
          pass: "somestring",
          type: "password",
          collect_type: "password",
          active: true
        }
      )
      aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ip nhrp authentication somestring')
    end
    
    context 'username privilege secret' do
      it 'with password type 0' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Username 'someusername' with Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "username someusername privilege 0 secret 0 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.username_password", "text/plain", "127.0.0.1", "someusername_level0:1511021F0725", "username_password.txt", "Cisco IOS Username and Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "someusername",
            pass: "1511021F0725",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'username someusername privilege 0 secret 0 1511021F0725')
      end
      
      it 'with password type 5' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Username 'someusername' with MD5 Encrypted Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "username someusername privilege 0 secret 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.username_password_hash", "text/plain", "127.0.0.1", "someusername_level0:1511021F0725",
          "username_password_hash.txt", "Cisco IOS Username and Password Hash (MD5)"
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'username someusername privilege 0 secret 5 1511021F0725')
      end

    
      it 'with password type 7' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Username 'someusername' with Decrypted Password: cisco")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "username someusername privilege 0 secret 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.username_password", "text/plain", "127.0.0.1", "someusername_level0:cisco", "username_password.txt", "Cisco IOS Username and Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "someusername",
            pass: "cisco",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'username someusername privilege 0 secret 7 1511021F0725')
      end
    end
    
    context 'username secret' do
      it 'with password type 0' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Username 'someusername' with Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "username someusername secret 0 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.username_password", "text/plain", "127.0.0.1", "someusername:1511021F0725", "username_password.txt",
          "Cisco IOS Username and Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "someusername",
            pass: "1511021F0725",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'username someusername secret 0 1511021F0725')
      end
      
      it 'with password type 5' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Username 'someusername' with MD5 Encrypted Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "username someusername secret 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.username_password_hash", "text/plain", "127.0.0.1", "someusername:1511021F0725", "username_password_hash.txt",
          "Cisco IOS Username and Password Hash (MD5)"
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'username someusername secret 5 1511021F0725')
      end

    
      it 'with password type 7' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Username 'someusername' with Decrypted Password: cisco")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "username someusername secret 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.username_password", "text/plain", "127.0.0.1", "someusername:cisco", "username_password.txt",
          "Cisco IOS Username and Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "someusername",
            pass: "cisco",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'username someusername secret 7 1511021F0725')
      end
    end
    
    context 'ppp.*username secret' do
      it 'with password type 0' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 PPP Username: someusername Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "ppp123username someusername secret 0 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.ppp_username_password", "text/plain", "127.0.0.1", "someusername:1511021F0725", "ppp_username_password.txt",
          "Cisco IOS PPP Username and Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "someusername",
            pass: "1511021F0725",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ppp123username someusername secret 0 1511021F0725')
      end
      
      it 'with password type 5' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 PPP Username someusername MD5 Encrypted Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "ppp123username someusername secret 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.ppp_username_password_hash", "text/plain", "127.0.0.1", "someusername:1511021F0725", "ppp_username_password_hash.txt",
          "Cisco IOS PPP Username and Password Hash (MD5)"
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ppp123username someusername secret 5 1511021F0725')
      end

    
      it 'with password type 7' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 PPP Username: someusername Decrypted Password: cisco")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "ppp123username someusername secret 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.ppp_username_password", "text/plain", "127.0.0.1", "someusername:cisco", "ppp_username_password.txt",
          "Cisco IOS PPP Username and Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "someusername",
            pass: "cisco",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ppp123username someusername secret 7 1511021F0725')
      end
    end
    
    context 'ppp chap secret' do
      it 'with password type 0' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "ppp chap secret 0 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.ppp_password", "text/plain", "127.0.0.1", "1511021F0725", "ppp_password.txt", "Cisco IOS PPP Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "",
            pass: "1511021F0725",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ppp chap secret 0 1511021F0725')
      end
      
      it 'with password type 5' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 PPP CHAP MD5 Encrypted Password: 1511021F0725")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "ppp chap secret 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.ppp_password_hash", "text/plain", "127.0.0.1", "1511021F0725", "ppp_password_hash.txt",
          "Cisco IOS PPP Password Hash (MD5)"
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ppp chap secret 5 1511021F0725')
      end

    
      it 'with password type 7' do
        expect(aux_cisco).to receive(:print_good).with("127.0.0.1:1337 PPP Decrypted Password: cisco")
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.config", "text/plain", "127.0.0.1", "ppp chap secret 7 1511021F0725", "config.txt", "Cisco IOS Configuration"
        )
        expect(aux_cisco).to receive(:store_loot).with(
          "cisco.ios.ppp_password", "text/plain", "127.0.0.1", "cisco", "ppp_password.txt", "Cisco IOS PPP Password"
        )
        expect(aux_cisco).to receive(:store_cred).with(
          {
            host: "127.0.0.1",
            port: 1337,
            user: "",
            pass: "cisco",
            type: "password",
            collect_type: "password",
            active: true
          }
        )
        aux_cisco.cisco_ios_config_eater('127.0.0.1',1337,'ppp chap secret 7 1511021F0725')
      end
    end
    
  end
  
end
