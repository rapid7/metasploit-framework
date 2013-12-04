require 'spec_helper'

describe Metasploit::Framework::Module::Target::Synchronization::TargetPlatforms do
  include_context 'database cleaner'
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

  let(:platform_count) do
    looping_minimum = 2
    total = Metasploit::Model::Platform.fully_qualified_name_set.length
    Random.rand(looping_minimum .. total)
  end

  let(:destination) do
    module_target
  end

  let(:module_target) do
    FactoryGirl.build(
        :mdm_module_target,
        target_platforms_length: 0
    )
  end

  let(:msf_module_target) do
    Msf::Module::Target.new(
        msf_module_target_name,
        'Platform' => msf_module_target_platform_fully_qualified_names
    )
  end

  let(:msf_module_target_platform_fully_qualified_names) do
    Metasploit::Model::Platform.fully_qualified_name_set.to_a.sample(platform_count)
  end

  let(:msf_module_target_name) do
    FactoryGirl.generate :metasploit_model_module_target_name
  end

  it_should_behave_like 'Metasploit::Framework::Scoped::Synchronization::Platform',
                        join_association: :target_platforms,
                        join_class: Mdm::Module::Target::Platform do
    def persistable_destination
      FactoryGirl.build(
          :mdm_module_target
      )
    end
  end
end