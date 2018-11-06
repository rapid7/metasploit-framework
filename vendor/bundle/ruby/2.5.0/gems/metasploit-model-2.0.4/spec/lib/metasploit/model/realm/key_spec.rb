RSpec.describe Metasploit::Model::Realm::Key do
  context 'CONSTANTS' do
    context 'ACTIVE_DIRECTORY_DOMAIN' do
      subject(:active_directory_domain) do
        described_class::ACTIVE_DIRECTORY_DOMAIN
      end

      it { is_expected.to eq('Active Directory Domain') }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'ALL' do
      subject(:all) do
        described_class::ALL
      end

      it { is_expected.to include described_class::ACTIVE_DIRECTORY_DOMAIN }
      it { is_expected.to include described_class::ORACLE_SYSTEM_IDENTIFIER }
      it { is_expected.to include described_class::POSTGRESQL_DATABASE }
      it { is_expected.to include described_class::WILDCARD }
    end

    context 'ORACLE_SYSTEM_IDENTIFIER' do
      subject(:oracle_system_identifier) do
        described_class::ORACLE_SYSTEM_IDENTIFIER
      end

      it { is_expected.to eq('Oracle System Identifier') }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'POSTGRESQL DATABASE' do
      subject(:postgresql_database) do
        described_class::POSTGRESQL_DATABASE
      end

      it { is_expected.to eq('PostgreSQL Database') }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'WILDCARD' do
      subject(:wildcard) do
        described_class::WILDCARD
      end

      it { is_expected.to eq('*') }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'SHORT_NAMES' do
      subject { described_class::SHORT_NAMES }
      it 'should have String keys' do
        subject.keys.each { |key|
          expect(key).to be_a(String)
        }
      end
      context 'values' do
        subject { described_class::SHORT_NAMES.values.sort }
        it { is_expected.to match_array(described_class::ALL.sort) }
      end
    end
  end
end
