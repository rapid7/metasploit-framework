# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/ldap/client'

RSpec.describe Rex::Proto::LDAP::Client do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }

  subject do
    client = described_class.new(host: host, port: port)
    client
  end

  it_behaves_like 'session compatible client'

  let(:base_dn) { 'DC=ldap,DC=example,DC=com' }
  let(:schema_dn) { 'CN=Schema,CN=Configuration,DC=ldap,DC=example,DC=com' }

  let(:root_dse_result_ldif) do
    "dn: \n" \
      "namingcontexts: #{base_dn}\n" \
      "namingcontexts: CN=Configuration,DC=ldap,DC=example,DC=com\n" \
      "namingcontexts: CN=Schema,CN=Configuration,DC=ldap,DC=example,DC=com\n" \
      "namingcontexts: DC=DomainDnsZones,DC=ldap,DC=example,DC=com\n" \
      "namingcontexts: DC=ForestDnsZones,DC=ldap,DC=example,DC=com\n" \
      "supportedldapversion: 2\n" \
      "supportedldapversion: 3\n" \
      "supportedsaslmechanisms: GSS-SPNEGO\n" \
      "supportedsaslmechanisms: GSSAPI\n" \
      "supportedsaslmechanisms: NTLM\n"
  end

  let(:schema_naming_context) do
    "dn: \n" \
      "schemanamingcontext: #{schema_dn}\n"
  end

  let(:empty_response) do
    "dn: \n"
  end

  let(:schema_naming_context_result) do
    root_dse_dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(schema_naming_context))
    root_dse_dataset.to_entries
  end

  let(:root_dse_result) do
    root_dse_dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(root_dse_result_ldif))
    root_dse_dataset.to_entries[0]
  end

  let(:empty_response_result) do
    root_dse_dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(empty_response))
    root_dse_dataset.to_entries
  end

  describe '#naming_contexts' do

    before(:each) do
      allow(subject).to receive(:search_root_dse).and_return(root_dse_result)
    end

    it 'should cache the result' do
      expect(subject).to receive(:search_root_dse)
      subject.naming_contexts
      expect(subject).not_to receive(:search_root_dse)
      subject.naming_contexts
    end

    context 'when no naming contexts are available' do
      let(:root_dse_result_ldif) do
        "dn: \n" \
          "supportedldapversion: 2\n" \
          "supportedldapversion: 3\n" \
          "supportedsaslmechanisms: GSS-SPNEGO\n" \
          "supportedsaslmechanisms: GSSAPI\n" \
          "supportedsaslmechanisms: NTLM\n"
      end

      it 'returns an empty array' do
        expect(subject.naming_contexts).to be_empty
      end
    end

    context 'when naming contexts are available' do
      it 'contains naming contexts' do
        expect(subject.naming_contexts).not_to be_empty
      end
    end
  end

  describe '#base_dn' do

    before(:each) do
      allow(subject).to receive(:search_root_dse).and_return(root_dse_result)
    end

    it 'should cache the result' do
      expect(subject).to receive(:discover_base_dn).and_call_original
      subject.base_dn
      expect(subject).not_to receive(:discover_base_dn)
      subject.base_dn
    end

    context 'when no naming contexts are available' do
      let(:root_dse_result_ldif) do
        "dn: \n" \
          "supportedldapversion: 2\n" \
          "supportedldapversion: 3\n" \
          "supportedsaslmechanisms: GSS-SPNEGO\n" \
          "supportedsaslmechanisms: GSSAPI\n" \
          "supportedsaslmechanisms: NTLM\n"
      end

      it 'should not find the base dn' do
        expect(subject.base_dn).to be_nil
      end
    end

    context 'when naming contexts are available' do
      it 'contains naming contexts' do
        expect(subject.base_dn).to eql(base_dn)
      end
    end
  end

  describe '#schema_dn' do

    before(:each) do
      allow(subject).to receive(:search).and_return(schema_naming_context_result)
    end

    it 'should cache the result' do
      expect(subject).to receive(:discover_schema_naming_context).and_call_original
      subject.schema_dn
      expect(subject).not_to receive(:discover_schema_naming_context)
      subject.schema_dn
    end

    context 'when the response does not contain the schema_dn' do
      before(:each) do
        allow(subject).to receive(:search).and_return(empty_response_result)
      end

      it 'does not find the schema_dn' do
        expect(subject.schema_dn).to be_nil
      end
    end

    context 'when the response does contain the schema_dn' do
      it 'finds the schema_dn' do
        expect(subject.schema_dn).to eql(schema_dn)
      end
    end
  end
end
