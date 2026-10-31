require 'spec_helper'

RSpec.describe Msf::Post::Windows::LDAP do
  subject(:ldap) { double('Windows LDAP').extend(described_class) }

  describe '#dn_to_domain' do
    it 'converts uppercase domain components' do
      expect(ldap.dn_to_domain('DC=example,DC=com')).to eq('example.com')
    end

    it 'converts lowercase domain components' do
      expect(ldap.dn_to_domain('dc=example,dc=com')).to eq('example.com')
    end

    it 'converts mixed-case attributes while preserving their values' do
      expect(ldap.dn_to_domain('dC=Example,Dc=COM')).to eq('Example.COM')
    end

    it 'ignores the organizational unit before the domain components' do
      expect(ldap.dn_to_domain('OU=Users,dc=example,dc=com')).to eq('example.com')
    end

    it 'does not treat dc= text within an OU value as a domain component' do
      expect(ldap.dn_to_domain('OU=dc=archive,DC=example,DC=com')).to eq('example.com')
    end

    it 'does not treat text following an escaped comma as a new attribute' do
      expect(ldap.dn_to_domain('OU=archive\\,dc=backup,DC=example,DC=com')).to eq('example.com')
    end

    it 'leaves a DN without domain components unchanged' do
      expect(ldap.dn_to_domain('OU=dc=archive,CN=Users')).to eq('OU=dc=archive,CN=Users')
    end

    it 'leaves DNS domain names unchanged' do
      expect(ldap.dn_to_domain('Example.COM')).to eq('Example.COM')
    end

    it 'preserves inputs that do not parse as a DN' do
      expect(ldap.dn_to_domain('example=value,not-a-component')).to eq('example=value,not-a-component')
    end
  end

  describe '#query' do
    let(:domain) { 'dc=example,dc=com' }
    let(:filter) { '(objectClass=user)' }
    let(:fields) { ['sAMAccountName'] }
    let(:results) { { results: [] } }
    let(:session) { double('Session', commands: []) }

    before do
      allow(ldap).to receive(:session).and_return(session)
      allow(ldap).to receive(:datastore).and_return({ 'DOMAIN' => domain })
      allow(ldap).to receive(:bind_default_ldap_server).with(500, 'example.com').and_yield(123)
      allow(ldap).to receive(:query_ldap).with(123, domain, 2, filter, fields).and_return(results)
    end

    it 'binds using the DNS domain while preserving the lowercase search base' do
      expect(ldap.query(filter, 500, fields, domain)).to eq(results)
    end

    it 'does not rediscover a naming context when a lowercase DN was supplied' do
      expect(ldap).not_to receive(:get_default_naming_context)

      ldap.query(filter, 500, fields, domain)
    end

    it 'accepts a lowercase DN from the datastore' do
      expect(ldap.query(filter, 500, fields)).to eq(results)
    end

    context 'with uppercase domain components' do
      let(:domain) { 'DC=example,DC=com' }

      it 'preserves the existing uppercase behavior' do
        expect(ldap.query(filter, 500, fields, domain)).to eq(results)
      end
    end

    context 'with mixed-case domain components' do
      let(:domain) { 'dC=example,Dc=com' }

      it 'uses the original DN as the search base' do
        expect(ldap.query(filter, 500, fields, domain)).to eq(results)
      end
    end

    context 'with a DNS domain name' do
      let(:domain) { 'example.com' }

      it 'discovers the naming context before querying' do
        expect(ldap).to receive(:get_default_naming_context).with(domain).and_return('dc=example,dc=com')
        expect(ldap).to receive(:query_ldap).with(123, 'dc=example,dc=com', 2, filter, fields).and_return(results)

        expect(ldap.query(filter, 500, fields, domain)).to eq(results)
      end
    end

    context 'with dc= text inside an OU value' do
      let(:domain) { 'OU=dc=archive,DC=example,DC=com' }

      it 'binds to the domain components and preserves the full search base' do
        expect(ldap.query(filter, 500, fields, domain)).to eq(results)
      end
    end

    context 'with an escaped comma inside an OU value' do
      let(:domain) { 'OU=archive\\,dc=backup,DC=example,DC=com' }

      it 'ignores the embedded dc= text when choosing the bind domain' do
        expect(ldap.query(filter, 500, fields, domain)).to eq(results)
      end
    end
  end
end
