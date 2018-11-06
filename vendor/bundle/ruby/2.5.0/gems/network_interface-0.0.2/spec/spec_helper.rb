$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
require 'network_interface'
require 'rspec'
require 'rspec/autorun'

RSpec.configure do |config|
end

def friendly_interface_names
  interfaces = NetworkInterface.interfaces
  interface_names ||= begin
    h = {}
    interfaces.each do |interface|
      info = NetworkInterface.interface_info(interface)
      name = if info && info.has_key?('name')
        info['name']
      else
        interface
      end
      h[name] = interface
    end
    h
  end
  interface_names
end

if RUBY_PLATFORM =~ /i386-mingw32/
  def system_interfaces
    ipconfig = `ipconfig`
    ipconfig_array = ipconfig.split("\n").reject {|s| s.empty?}
    
    getmac = `getmac -nh`
    getmac_array = getmac.split("\n").reject {|s| s.empty?}
    getmac_array.map!{|element| element.split(" ")}
    getmac_hash = getmac_array.inject({}) do |hash, array|
      hash.merge!({array[1][/\{(.*)\}/,1] => array[0].gsub("-",":").downcase})
    end
    
    interfaces = {}
    @key = nil
    ipconfig_array.each do |element|
      if element.start_with? " "
        case element
        when /IPv6 Address.*: (.*)/
          # interfaces[@key][:ipv6] = $1
        when /IPv4 Address.*: (.*)/
          interfaces[@key][:ipv4] = $1
          interfaces[@key][:mac] = getmac_hash[@key[/\{(.*)\}/,1]]
        end
      elsif element[/Windows IP Configuration/]
      elsif element[/Ethernet adapter (.*):/]
        @key = friendly_interface_names[$1]
        interfaces[@key] = {}
      else
        @key = element[/(.*):/,1]
        interfaces[@key] = {}
      end
    end
    
    interfaces
  end

else 
  def system_interfaces
    ifconfig = `/sbin/ifconfig`
    ifconfig_array = ifconfig.split("\n")
    ifconfig_array.map!{|element| element.split("\n")}
    ifconfig_array.flatten!
    interfaces = {}
    @key = nil
    ifconfig_array.each do |element|
      if element.start_with?("\t") || element.start_with?(" ")
        case element
        when /ether ((\w{2}\:){5}(\w{2}))/
          interfaces[@key][:mac] = $1
        when /inet6 (.*) prefixlen/
          interfaces[@key][:ipv6] = $1
        when /inet ((\d{1,3}\.){3}\d{1,3}).*broadcast ((\d{1,3}\.){3}\d{1,3})/
          interfaces[@key][:ipv4] = $1
          interfaces[@key][:broadcast] = $3
        when /addr:((\d{1,3}\.){3}\d{1,3})\s+Bcast:((\d{1,3}\.){3}\d{1,3})/i
          interfaces[@key][:ipv4] = $1
          interfaces[@key][:broadcast] = $3
        end
      else
        @key = element.split(' ').first[/(\w*)/,1]
        interfaces[@key] = {}
        if element[/HWaddr ((\w{2}\:){5}(\w{2}))/]
          interfaces[@key][:mac] = $1
        end
      end
    end
    interfaces
  end

end

def system_interfaces_with_addresses
  interfaces = {}
  system_interfaces.each do |key, value|
    if value.has_key? :ipv4
      interfaces[key] = value
    end
  end
  interfaces
end
