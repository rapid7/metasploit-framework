# -*- coding:binary -*-
require 'spec_helper'
require 'net/dns'


RSpec.describe Rex::Proto::DNS::CustomNameserverProvider do
  def packet_for(name)
    packet = Net::DNS::Packet.new(name, Net::DNS::A, Net::DNS::IN)
    Rex::Proto::DNS::Packet.encode_drb(packet)
  end

  let(:default_nameserver) do
    '192.0.2.10'
  end

  let(:metasploit_nameserver) do
    '192.0.2.20'
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

  subject(:dns_resolver) do
    dns_resolver = Rex::Proto::DNS::CachedResolver.new(config)
    dns_resolver.nameservers = [default_nameserver]
    dns_resolver.extend(Rex::Proto::DNS::CustomNameserverProvider)
    dns_resolver.add_upstream_rule([metasploit_nameserver], wildcard: '*.metasploit.com', index: 0)
    dns_resolver.set_framework(framework_with_dns_enabled)
    dns_resolver
  end

  context 'When a condition matches' do
    it 'The correct resolver is returned' do
      packet = packet_for('subdomain.metasploit.com')
      ns = dns_resolver.upstream_resolvers_for_packet(packet)
      expect(ns).to eq([
        Rex::Proto::DNS::UpstreamResolver.create_dns_server(metasploit_nameserver)
      ])
    end
  end

  context 'When no conditions match' do
    it 'The default resolver is returned' do
      packet = packet_for('subdomain.test.lan')
      ns = dns_resolver.upstream_resolvers_for_packet(packet)
      expect(ns).to eq([
        Rex::Proto::DNS::UpstreamResolver.create_static,
        Rex::Proto::DNS::UpstreamResolver.create_dns_server(default_nameserver)
      ])
    end
  end
end
