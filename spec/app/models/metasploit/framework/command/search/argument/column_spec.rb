require 'spec_helper'

describe Metasploit::Framework::Command::Search::Argument::Column do
  column_names = [
      'description',
      'disclosed_on',
      'license',
      'name',
      'privileged',
      'stance',
      'actions.name',
      'architectures.abbreviation',
      'architectures.bits',
      'architectures.endianness',
      'architectures.family',
      'authorities.abbreviation',
      'authors.name',
      'email_addresses.domain',
      'email_addresses.full',
      'email_addresses.local',
      'module_class.full_name',
      'module_class.module_type',
      'module_class.payload_type',
      'module_class.reference_name',
      'platforms.fully_qualified_name',
      'rank.name',
      'rank.number',
      'references.designation',
      'references.url',
      'targets.name'
  ]

  context 'validations' do
    context 'value' do
      subject(:argument) do
        described_class.new(
            value: value
        )
      end

      column_names.each do |column_name|
        context "with #{column_name}" do
          let(:value) do
            column_name
          end

          it { should be_valid }
        end
      end

      non_column_operator_names = [
          'app',
          'author',
          'bid',
          'cve',
          'edb',
          'os',
          'osvdb',
          'platform',
          'ref',
          'text'
      ]

      non_column_operator_names.each do |non_column_operator_name|
        context "with #{non_column_operator_name}" do
          let(:value) do
            non_column_operator_name
          end

          it { should_not be_valid }
        end
      end
    end
  end

  context 'set' do
    subject(:set) do
      described_class.set
    end

    it { should == Set.new(column_names) }
  end
end