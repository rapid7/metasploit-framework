# -*- coding:binary -*-
require 'spec_helper'

# rpc_hosts resolves the workspace through framework.db but runs the actual CIDR
# query against the local ApplicationRecord connection.  Under REMOTE_DB the active
# data service is a separate process on its own database connection that cannot see
# the rows this spec creates inside the example's transactional fixture, so the
# lookup comes back empty.  Guard the spec like the other DB specs (host.rb,
# service.rb, cred.rb, vuln.rb, note.rb, ...).  The non-REMOTE_DB rspec jobs still
# run it and exercise the CIDR filtering.
unless ENV['REMOTE_DB']
  RSpec.describe Msf::RPC::RPC_Db do
    include_context 'Msf::DBManager'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'
    include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false

    let(:service) { Msf::RPC::Service.new(framework) }
    let(:rpc_db) { Msf::RPC::RPC_Db.new(service) }

    let(:workspace_name) { 'cidr_filtering_spec' }
    # A fixed, non-overlapping subnet so the assertions are independent of any other
    # host data in the database.
    let(:subnet_hosts) { %w[10.20.30.1 10.20.30.100 10.20.30.200] }
    let(:outside_host) { '10.20.31.1' }

    before(:each) do
      framework.db.add_workspace(workspace_name)
      (subnet_hosts + [outside_host]).each do |ip|
        rpc_db.rpc_report_host('workspace' => workspace_name, 'host' => ip, 'state' => Msf::HostState::Alive)
      end
    end

    describe '#rpc_hosts' do
      def returned_addresses(addresses)
        result = rpc_db.rpc_hosts('workspace' => workspace_name, 'addresses' => addresses)
        result[:hosts].map { |host| host[:address] }
      end

      it 'returns all subnet hosts for a network-address CIDR' do
        returned = returned_addresses('10.20.30.0/24')
        expect(returned).to match_array(subnet_hosts)
        expect(returned).not_to include(outside_host)
      end

      it 'returns all subnet hosts when the CIDR uses a host address rather than the network address' do
        # Regression test for the IPAddr#to_string bug: passing "10.20.30.100/24"
        # must match the whole /24 subnet, not just the /32 for 10.20.30.0.
        # IPAddr#to_string strips the prefix ("10.20.30.0"), which PostgreSQL then
        # casts as a /32, returning 0 results.  IPAddr#cidr preserves it ("10.20.30.0/24").
        returned = returned_addresses('10.20.30.100/24')
        expect(returned).to match_array(subnet_hosts)
        expect(returned).not_to include(outside_host)
      end

      it 'returns only the matching host for a /32 CIDR' do
        expect(returned_addresses('10.20.30.100/32')).to eq(['10.20.30.100'])
      end

      it 'returns only the matching host for a bare IP address' do
        expect(returned_addresses('10.20.30.100')).to eq(['10.20.30.100'])
      end
    end
  end
end
