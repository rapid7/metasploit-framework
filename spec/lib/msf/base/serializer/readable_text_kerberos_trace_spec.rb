# -*- coding: binary -*-

require 'spec_helper'
require 'rex/text'

RSpec.describe Msf::Serializer::ReadableText do
  let(:indent_string) { '' }

  def kerberos_auth_options(protocol:, auth_methods:)
    mixin = Class.new.extend(Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Options)
    mixin.kerberos_auth_options(protocol: protocol, auth_methods: auth_methods)
  end

  let(:aux_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      def initialize
        super(
          'Name' => 'mock module',
          'Description' => 'mock module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )
      end
    end

    mod = mod_klass.new
    mock_framework = instance_double(::Msf::Framework, datastore: Msf::DataStore.new)
    allow(mod).to receive(:framework).and_return(mock_framework)
    mod
  end

  before(:each) do
    allow(Rex::Text::Table).to receive(:wrapped_tables?).and_return(true)
  end

  describe '.dump_advanced_options' do
    it 'includes the kerberos trace options' do
      aux_mod.send(
        :register_advanced_options,
        kerberos_auth_options(protocol: 'Winrm', auth_methods: Msf::Exploit::Remote::AuthOption::WINRM_OPTIONS)
      )

      expect(described_class.dump_advanced_options(aux_mod, indent_string)).to include(
        'KerberosTicketTrace               false'
      )
      expect(described_class.dump_advanced_options(aux_mod, indent_string)).to include(
        'KerberosTicketTraceLevel          summary'
      )
    end
  end

  describe '.dump_evasion_options' do
    it 'includes the kerberos trace options' do
      aux_mod.send(
        :register_evasion_options,
        kerberos_auth_options(protocol: 'Winrm', auth_methods: Msf::Exploit::Remote::AuthOption::WINRM_OPTIONS)
      )

      expect(described_class.dump_evasion_options(aux_mod, indent_string)).to include(
        'KerberosTicketTrace               false'
      )
      expect(described_class.dump_evasion_options(aux_mod, indent_string)).to include(
        'KerberosTicketTraceLevel          summary'
      )
    end
  end
end
