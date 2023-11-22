# -*- coding:binary -*-
require 'spec_helper'
require 'net/dns'


RSpec.describe Rex::Proto::DNS::CustomNameserverProvider do
  def packet_for(name)
    packet = Net::DNS::Packet.new(name, Net::DNS::A, Net::DNS::IN)
    Rex::Proto::DNS::Packet.encode_drb(packet)
  end

  let(:base_nameserver) do
    '1.2.3.4'
  end

  let(:ruleless_nameserver) do
    '1.2.3.5'
  end

  let(:ruled_nameserver) do
    '1.2.3.6'
  end

  let(:ruled_nameserver2) do
    '1.2.3.7'
  end

  let(:ruled_nameserver3) do
    '1.2.3.8'
  end

  let (:config) do
    {:dns_cache_no_start => true}
  end

  let (:framework_with_dns_enabled) do
    framework = Object.new
    def framework.features
      f = Object.new
      def f.enabled?(_name)
        true
      end

      f
    end

    framework
  end

  subject(:many_ruled_provider) do
    dns_resolver = Rex::Proto::DNS::CachedResolver.new(config)
    dns_resolver.extend(Rex::Proto::DNS::CustomNameserverProvider)
    dns_resolver.nameservers = [base_nameserver]
    dns_resolver.add_nameserver([], ruleless_nameserver, nil)
    dns_resolver.add_nameserver(['*.metasploit.com'], ruled_nameserver, nil)
    dns_resolver.add_nameserver(['*.metasploit.com'], ruled_nameserver2, nil)
    dns_resolver.add_nameserver(['*.notmetasploit.com'], ruled_nameserver3, nil)
    dns_resolver.set_framework(framework_with_dns_enabled)

    dns_resolver
  end

  subject(:ruled_provider) do
    dns_resolver = Rex::Proto::DNS::CachedResolver.new(config)
    dns_resolver.extend(Rex::Proto::DNS::CustomNameserverProvider)
    dns_resolver.nameservers = [base_nameserver]
    dns_resolver.add_nameserver([], ruleless_nameserver, nil)
    dns_resolver.add_nameserver(['*.metasploit.com'], ruled_nameserver, nil)
    dns_resolver.set_framework(framework_with_dns_enabled)

    dns_resolver
  end

  subject(:ruleless_provider) do
    dns_resolver = Rex::Proto::DNS::CachedResolver.new(config)
    dns_resolver.extend(Rex::Proto::DNS::CustomNameserverProvider)
    dns_resolver.nameservers = [base_nameserver]
    dns_resolver.add_nameserver([], ruleless_nameserver, nil)
    dns_resolver.set_framework(framework_with_dns_enabled)

    dns_resolver
  end

  subject(:empty_provider) do
    dns_resolver = Rex::Proto::DNS::CachedResolver.new(config)
    dns_resolver.extend(Rex::Proto::DNS::CustomNameserverProvider)
    dns_resolver.nameservers = [base_nameserver]
    dns_resolver.set_framework(framework_with_dns_enabled)

    dns_resolver
  end

  context 'When no nameserver is configured' do
   it 'The resolver base is returned' do
     packet = packet_for('subdomain.metasploit.com')
     ns = empty_provider.nameservers_for_packet(packet)
     expect(ns).to eq([[base_nameserver, {}]])
   end
  end

  context 'When a base nameserver is configured' do
   it 'The base nameserver is returned' do
     packet = packet_for('subdomain.metasploit.com')
     ns = ruleless_provider.nameservers_for_packet(packet)
     expect(ns).to eq([[ruleless_nameserver, {}]])
   end
  end

  context 'When a nameserver rule is configured and a rule entry matches' do
   it 'The correct nameserver is returned' do
     packet = packet_for('subdomain.metasploit.com')
     ns = ruled_provider.nameservers_for_packet(packet)
     expect(ns).to eq([[ruled_nameserver, {}]])
    end
  end

  context 'When a nameserver rule is configured and no rule entry is applicable' do
   it 'The base nameserver is returned when no rule entry' do
     packet = packet_for('subdomain.notmetasploit.com')
     ns = ruled_provider.nameservers_for_packet(packet)
     expect(ns).to eq([[ruleless_nameserver, {}]])
   end
  end

  context 'When many rules are configured' do
   it 'Returns multiple entries if multiple rules match' do
     packet = packet_for('subdomain.metasploit.com')
     ns = many_ruled_provider.nameservers_for_packet(packet)
     expect(ns).to eq([[ruled_nameserver, {}], [ruled_nameserver2, {}]])
   end
  end

  context 'When a packet contains multiple questions that have different nameserver results' do
   it 'Throws an error' do
     packet = packet_for('subdomain.metasploit.com')
     q = Dnsruby::Question.new('subdomain.notmetasploit.com', Dnsruby::Types::A, Dnsruby::Classes::IN)

     packet.question.append(q)
     expect {many_ruled_provider.nameservers_for_packet(packet)}.to raise_error(ResolverError)
   end
  end
end