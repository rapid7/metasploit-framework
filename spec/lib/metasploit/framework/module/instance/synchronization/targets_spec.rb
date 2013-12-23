require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Synchronization::Targets do
  include_context 'database cleaner'
  include_context 'metasploit_super_class_by_module_type'
  include_context 'Msf::Simple::Framework'

  subject(:synchronization) do
    described_class.new(
        destination: module_instance,
        source: metasploit_instance
    )
  end

  #
  # methods
  #

  def format_architectures(architectures)
    architectures.map(&:abbreviation)
  end

  def format_platforms(platforms)
    platforms.map(&:fully_qualified_name)
  end

  def module_target_options(module_target)
    architectures = module_target.target_architectures.map(&:architecture)
    formatted_architectures = format_architectures(architectures)

    platforms = module_target.target_platforms.map(&:platform)
    formatted_platforms = format_platforms(platforms)

    {
        'Arch' => formatted_architectures,
        'Platform' => formatted_platforms
    }
  end

  #
  # lets
  #

  let(:expected_module_targets) do
    FactoryGirl.build_list(
        :mdm_module_target,
        2
    )
  end

  let(:formatted_targets) do
    expected_module_targets.collect { |module_target|
      [
          module_target.name,
          module_target_options(module_target)
      ]
    }
  end

  let(:metasploit_class) do
    formatted_targets = self.formatted_targets

    Class.new(metasploit_super_class) do
      define_method(:initialize) do |info={}|
        super(
            merge_info(
                info,
                'Targets' => formatted_targets
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

  let(:module_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: module_type
    )
  end

  let(:module_instance) do
    FactoryGirl.build(
        :mdm_module_instance,
        targets_length: 0,
        module_class: module_class
    )
  end

  let(:module_type) do
    module_types.sample
  end

  let(:module_types) do
    Metasploit::Model::Module::Instance.module_types_that_allow(:targets)
  end

  #
  # Callbacks
  #

  before(:each) do
    metasploit_class.stub(module_class: module_class)
  end

  context 'CONSTANTS' do
    context 'ALLOW_BY_ATTRIBUTE' do
      subject(:allow_by_attribute) do
        described_class::ALLOW_BY_ATTRIBUTE
      end

      its([:targets]) { should be_true }
    end
  end

  context 'synchronization' do
    it_should_behave_like 'Metasploit::Framework::Synchronizes#synchronizes',
                          :target_architectures,
                          :target_platforms,
                          for: 'Module::Target'

    it_should_behave_like 'Metasploit::Framework::Synchronizes#synchronizes',
                          :module_architectures,
                          :module_platforms,
                          for: 'Module::Instance'
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

      it { should be_true }
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

      it { should be_false }
    end

    context 'with post' do
      let(:module_type) do
        'post'
      end

      it { should be_false }
    end
  end

  context '#destination_attributes_set' do
    subject(:destination_attributes_set) do
      synchronization.destination_attributes_set
    end

    context 'with new record' do
      it { should == Set.new }
    end

    context 'without new record' do
      #
      # lets
      #

      let(:module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            targets_length: 2,
            module_class: module_class
        )
      end

      #
      # callbacks
      #

      before(:each) do
        module_instance.save!
      end

      it 'should include Mdm::Module::Target#names' do
        destination_attributes_set.should == Set.new(module_instance.targets.map(&:name))
      end
    end
  end

  context '#destroy_removed' do
    subject(:destroy_removed) do
      synchronization.destroy_removed
    end

    context 'with new record' do
      it 'should not destroy anything' do
        ActiveRecord::Relation.any_instance.should_not_receive(:destroy_all)

        destroy_removed
      end
    end

    context 'without new record' do
      #
      # let!s
      #

      let(:module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            targets_length: 1,
            module_class: module_class
        )
      end

      #
      # callbacks
      #

      before(:each) do
        module_instance.save!

        synchronization.stub(removed_attributes_set: removed_attributes_set)
      end

      context 'with #removed_attributes_set' do
        let(:name) do
          FactoryGirl.generate :metasploit_model_module_target_name
        end

        let(:removed_attributes_set) do
          Set.new(
              [
                  name
              ]
          )
        end

        context 'with matching Mdm::Module::Target' do
          let(:module_instance) do
            FactoryGirl.build(
                :mdm_module_instance,
                module_class: module_class
            ).tap { |module_instance|
              FactoryGirl.build(
                  :mdm_module_target,
                  module_instance: module_instance,
                  name: name
              )
            }
          end

          it 'should destroy matching Mdm::Module::Target' do
            expect {
              destroy_removed
            }.to change(Mdm::Module::Target, :count).by(-1)
          end
        end

        context 'without matching Mdm::Module::Target' do
          it 'should not destroy any Mdm::Module::Targets' do
            expect {
              destroy_removed
            }.not_to change(Mdm::Module::Target, :count)
          end
        end
      end

      context 'without #removed_attributes_set' do
        let(:removed_attributes_set) do
          Set.new
        end

        it 'should not destroy anything' do
          ActiveRecord::Relation.any_instance.should_not_receive(:destroy_all)

          destroy_removed
        end
      end
    end
  end

  context '#module_target_by_name' do
    subject(:module_target_by_name) do
      synchronization.module_target_by_name
    end

    #
    # callbacks
    #

    context 'with #unchanged_module_targets' do
      #
      # lets
      #

      let(:module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            module_class: module_class,
            targets_length: 1
        )
      end

      let(:module_target) do
        module_instance.targets.first
      end

      let(:unchanged_attributes_set) do
        Set.new(
            [
                module_target.name
            ]
        )
      end

      #
      # callbacks
      #

      before(:each) do
        module_instance.save!

        synchronization.stub(unchanged_attributes_set: unchanged_attributes_set)
      end

      it 'should have Mdm::Module::Target from database' do
        found_module_target = module_target_by_name[module_target.name]
        found_module_target.should_not be_nil
        found_module_target.should be_persisted
      end
    end

    context 'with unknown name' do
      let(:built_module_target) do
        module_target_by_name[name]
      end

      let(:name) do
        FactoryGirl.generate :metasploit_model_module_target_name
      end

      it 'should build a Mdm::Module::Target with name' do
        built_module_target.should_not be_nil
        built_module_target.should be_a_new_record
        built_module_target.name.should == name
      end
    end
  end

  context '#scope' do
    subject(:scope) do
      synchronization.scope
    end

    context 'includes' do
      subject(:includes) do
        scope.includes_values.first
      end

      its([:target_architectures]) { :architecture }
      its([:target_platforms]) { :platform }
    end
  end

  context '#synchronize' do
    subject(:synchronize) do
      synchronization.synchronize
    end

    it 'should destroy_removed, synchronize module target associations and then synchronize them to module instance associations' do
      synchronization.should_receive(:destroy_removed).ordered
      synchronization.should_receive(:synchronize_module_target_associations).ordered
      synchronization.should_receive(:synchronize_module_instance_associations).ordered

      synchronize
    end
  end

  context '#synchronize_module_instance_associations' do
    subject(:synchronize_module_instance_associations) do
      synchronization.synchronize_module_instance_associations
    end

    it 'should enumerate synchronization_classes for Module::Instance' do
      described_class.should_receive(:synchronization_classes).with(for: 'Module::Instance')

      synchronize_module_instance_associations
    end

    context 'synchronization classes' do
      shared_context 'synchronizes with class' do |synchronization_class|
        it "should initialize #{synchronization_class}" do
          synchronization_class.should_receive(:new).with(destination: module_instance, source: metasploit_instance).and_call_original

          synchronize_module_instance_associations
        end

        it 'should validate before synchronizing' do
          synchronization_instance = double('Synchronization Instance')

          synchronization_class.should_receive(:new).and_return(synchronization_instance)
          synchronization_instance.should_receive(:valid!).ordered
          synchronization_instance.should_receive(:synchronize).ordered

          synchronize_module_instance_associations
        end
      end

      it_should_behave_like 'synchronizes with class', Metasploit::Framework::Module::Instance::Synchronization::ModuleArchitectures
      it_should_behave_like 'synchronizes with class', Metasploit::Framework::Module::Instance::Synchronization::ModulePlatforms
    end
  end

  context '#synchronize_module_target_associations' do
    subject(:synchronize_module_target_associations) do
      synchronization.synchronize_module_target_associations
    end

    #
    # lets
    #

    let(:msf_module_target) do
      Msf::Module::Target.new(name, {})
    end

    let(:name) do
      FactoryGirl.generate :metasploit_model_module_target_name
    end

    let(:source_targets) do
      [
          msf_module_target
      ]
    end

    #
    # callbacks
    #

    before(:each) do
      msf_module_target.metasploit_instance = metasploit_instance
      synchronization.stub(source_targets: source_targets)
    end

    it 'should lookup module_target in #module_target_by_name' do
      synchronization.module_target_by_name.should_receive(:[]).with(name).and_call_original

      synchronize_module_target_associations
    end

    it 'should enumerate synchronization_classes for Module::Target' do
      described_class.should_receive(:synchronization_classes).with(for: 'Module::Target')

      synchronize_module_target_associations
    end

    context 'synchronization classes' do
      shared_context 'synchronizes with class' do |synchronization_class|
        it "should initialize #{synchronization_class}" do
          synchronization_class.should_receive(:new) { |attributes={}|
            module_target = attributes[:destination]

            module_target.should be_a Mdm::Module::Target
            module_target.name.should == name

            source = attributes[:source]
            source.should == msf_module_target
          }.and_call_original

          synchronize_module_target_associations
        end

        it 'should validate before synchronizing' do
          synchronization_instance = double('Synchronization Instance')

          synchronization_class.should_receive(:new).and_return(synchronization_instance)
          synchronization_instance.should_receive(:valid!).ordered
          synchronization_instance.should_receive(:synchronize).ordered

          synchronize_module_target_associations
        end
      end

      it_should_behave_like 'synchronizes with class', Metasploit::Framework::Module::Target::Synchronization::TargetArchitectures
      it_should_behave_like 'synchronizes with class', Metasploit::Framework::Module::Target::Synchronization::TargetPlatforms
    end
  end

  context '#source_attributes_set' do
    subject(:source_attributes_set) do
      synchronization.source_attributes_set
    end

    it { should be_a Set }

    it 'should have target names' do
      source_attributes_set.should == Set.new(expected_module_targets.map(&:name))
    end
  end

  context 'source_targets' do
    subject(:source_targets) do
      synchronization.source_targets
    end

    context 'with NoMethodError' do
      #
      # lets
      #

      let(:error) do
        NoMethodError.new('message')
      end

      #
      # callbacks
      #

      before(:each) do
        metasploit_instance.should_receive(:targets).and_raise(error)
      end

      it { should == [] }

      it 'should log module instance error' do
        synchronization.should_receive(:log_module_instance_error).with(module_instance, error)

        source_targets
      end
    end

    context 'without NoMethodError' do
      it 'should be source.targets' do
        source_targets.should == metasploit_instance.targets
      end
    end
  end

  context '#unchanged_attributes_set' do
    subject(:unchanged_attributes_set) do
      synchronization.unchanged_attributes_set
    end

    #
    # Methods
    #

    def target_name_set
      2.times.each_with_object(Set.new) { |_, set|
        name = FactoryGirl.generate :metasploit_model_module_target_name
        set.add name
      }
    end

    #
    # lets
    #

    let(:destination_attributes_set) do
      intersection | destination_only
    end

    let(:destination_only) do
      target_name_set
    end

    let(:intersection) do
      target_name_set
    end

    let(:source_attributes_set) do
      intersection | source_only
    end

    let(:source_only) do
      target_name_set
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(destination_attributes_set: destination_attributes_set)
      synchronization.stub(source_attributes_set: source_attributes_set)
    end

    it 'should be intersection of #destination_attributes_set and #source_attributes_set' do
      unchanged_attributes_set.should == intersection
    end
  end

  context '#unchanged_module_targets' do
    subject(:unchanged_module_targets) do
      synchronization.unchanged_module_targets
    end

    context 'with new record' do
      it { should == [] }
    end

    context 'without new record' do
      let(:expected_module_targets) do
        module_instance.targets
      end

      let(:module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            module_class: module_class,
            targets_length: 2
        )
      end

      before(:each) do
        module_instance.save!
      end

      context 'with #unchanged_attributes_set' do
        it 'should have #unchanged_attributes_set' do
          synchronization.unchanged_attributes_set.should_not be_empty
        end

        it 'should be existing Mdm::Module::Targets' do
          unchanged_module_targets.should == expected_module_targets
        end
      end

      context 'without #unchanged_attributes_set' do
        before(:each) do
          synchronization.stub(unchanged_attributes_set: Set.new)
        end

        it { should == [] }
      end
    end
  end
end
