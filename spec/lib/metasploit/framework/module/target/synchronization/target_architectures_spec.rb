require 'spec_helper'

describe Metasploit::Framework::Module::Target::Synchronization::TargetArchitectures do
  include_context 'database seeds'
  include_context 'metasploit_super_class_by_module_type'
  include_context 'Msf::Simple::Framework'

  subject(:synchronization) do
    described_class.new(
        destination: destination,
        source: msf_module_target
    )
  end

  #
  # lets
  #

  let(:architecture_count) do
    looping_minimum = 2
    Random.rand(looping_minimum .. Metasploit::Model::Architecture::ABBREVIATIONS.length)
  end

  let(:destination) do
    module_target
  end

  let(:module_target) do
    FactoryGirl.build(
        :mdm_module_target,
        target_architectures_length: 0
    )
  end

  let(:msf_module_target) do
    Msf::Module::Target.new(
        msf_module_target_name,
        'Arch' => msf_module_target_architecture_abbreviations
    )
  end

  let(:msf_module_target_architecture_abbreviations) do
    Metasploit::Model::Architecture::ABBREVIATIONS.sample(architecture_count)
  end

  let(:msf_module_target_name) do
    FactoryGirl.generate :metasploit_model_module_target_name
  end

  #
  # callbacks
  #

  around(:each) do |example|
    with_established_connection do
      example.run
    end
  end

  it_should_behave_like 'Metasploit::Framework::Scoped::Synchronization::Architecture',
                        join_association: :target_architectures,
                        join_class: Mdm::Module::Target::Architecture do
    def persistable_destination
      FactoryGirl.build(
          :mdm_module_target
      )
    end
  end
end