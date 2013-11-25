require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Synchronization::ModulePlatforms do
  include_context 'database seeds'
  include_context 'metasploit_super_class_by_module_type'
  include_context 'Msf::Simple::Framework'

  subject(:synchronization) do
    described_class.new(
        destination: destination,
        source: metasploit_instance
    )
  end

  #
  # methods
  #

  def persistable_destination
    FactoryGirl.build(
        :mdm_module_instance,
        module_class: module_class
    )
  end

  #
  # lets
  #

  let(:destination) do
    module_instance
  end

  let(:formatted_platforms) do
    platforms.map(&:fully_qualified_name)
  end

  let(:metasploit_class) do
    formatted_platforms = self.formatted_platforms

    Class.new(metasploit_super_class) do
      define_method(:initialize) do |info={}|
        super(
            merge_info(
                info,
                'Platform' => formatted_platforms
            )
        )
      end
    end
  end

  let(:metasploit_instance) do
    metasploit_class.new(
        framework: framework
    )
  end

  let(:module_platforms_module_types) do
    Metasploit::Model::Module::Instance.module_types_that_allow(:module_platforms)
  end

  let(:module_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: module_type
    )
  end

  let(:module_instance) do
    FactoryGirl.build(
        :mdm_module_instance,
        module_class: module_class,
        module_platforms_length: 0,
        targets_length: 0
    )
  end

  let(:module_type) do
    module_types.sample
  end

  let(:module_types) do
    # payload are more complicated to build, so skip them
    module_platforms_module_types - targets_module_types - ['payload']
  end

  let(:platform_count) do
    looping_minimum = 2
    Random.rand(looping_minimum .. Mdm::Platform.count)
  end

  let(:platforms) do
    platform_count.times.collect {
      FactoryGirl.generate :mdm_platform
    }
  end

  let(:targets_module_types) do
    Metasploit::Model::Module::Instance.module_types_that_allow(:targets)
  end


  #
  # callbacks
  #

  around(:each) do |example|
    with_established_connection do
      example.run
    end
  end

  context 'CONSTANTS' do
    context 'ALLOW_BY_ATTRIBUTE' do
      subject(:allow_by_attribute) do
        described_class::ALLOW_BY_ATTRIBUTE
      end

      its([:module_platforms]) { should be_true }
      its([:targets]) { should be_false }
    end
  end

  context 'can_synchronize?' do
    subject(:can_synchronize?) do
      described_class.can_synchronize?(module_instance)
    end

    context 'with auxiliary' do
      let(:module_type) do
        'auxiliary'
      end

      it { should be_false }
    end

    context 'with encoder' do
      let(:module_type) do
        'encoder'
      end

      it { should be_false }
    end

    context 'with exploit' do
      let(:module_type) do
        'exploit'
      end

      it { should be_false }
    end

    context 'with nop' do
      let(:module_type) do
        'nop'
      end

      it { should be_false }
    end

    context 'with payload' do
      let(:module_type) do
        'payload'
      end

      it { should be_true }
    end

    context 'with post' do
      let(:module_type) do
        'post'
      end

      it { should be_true }
    end
  end

  context 'with targets' do
    let(:module_types) do
      targets_module_types
    end

    it_should_behave_like 'Metasploit::Framework::Scoped::Synchronization::Platform',
                          join_association: :module_platforms,
                          join_class: Mdm::Module::Platform

    context '#source_attributes_set' do
      subject(:source_attributes_set) do
        synchronization.source_attributes_set
      end

      let(:expected_architecture_abbreviation_set) do
        module_instance.targets.each_with_object(Set.new) { |module_target, set|
          module_target.target_architectures.each do |target_architecture|
            set.add target_architecture.architecture.abbreviation
          end
        }
      end

      it { should be_a Set }

      it 'should aggregate architecture abbreviations from target architectures' do
        source_attributes_set.should == expected_architecture_abbreviation_set
      end
    end
  end

  context 'without targets' do
    it_should_behave_like 'Metasploit::Framework::Scoped::Synchronization::Platform',
                          join_association: :module_platforms,
                          join_class: Mdm::Module::Platform

    context '#source_attributes_set' do
      subject(:source_attributes_set) do
        synchronization.source_attributes_set
      end

      it { should be_a Set }

      it 'should call #source_architecture_abbreviations' do
        synchronization.should_receive(:source_platform_list).and_return(Msf::Module::PlatformList.new)

        source_attributes_set
      end
    end
  end
end