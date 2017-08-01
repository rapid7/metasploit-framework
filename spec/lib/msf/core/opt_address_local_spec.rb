# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

RSpec.describe Msf::OptAddressLocal do
  iface = NetworkInterface.interfaces.collect do |iface|
    ip_address = NetworkInterface.addresses(iface).values.flatten.collect{|x| x['addr']}.select do |addr|
      begin
        IPAddr.new(addr).ipv4? && !addr[/^127.*/]
      rescue IPAddr::InvalidAddressError => e
        false
      end
    end.first
    {name: iface, addr: ip_address}
  end.select {|ni| ni[:addr]}.first
  
  valid_values = [
    { :value => "192.0.2.0",    :normalized => "192.0.2.0" },
    { :value => "127.0.0.1",    :normalized => "127.0.0.1" },
    { :value => "2001:db8::",   :normalized => "2001:db8::" },
    { :value => "::1",          :normalized => "::1" },
    { :value => iface[:name],   :normalized => iface[:addr]}
  ]
  
  invalid_values = [
    # Too many dots
    { :value => "192.0.2.0.0" },
    # Not enough
    { :value => "192.0.2" },
    # Non-string values
    { :value => true},
    { :value => 5 },
    { :value => []},
    { :value => [1,2]},
    { :value => {}},
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'address'

  let(:required_opt) {  Msf::OptAddressLocal.new('LHOST', [true, 'local address', '']) }
  
end
