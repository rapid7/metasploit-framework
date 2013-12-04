require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Synchronization::Actions do
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
  # lets
  #

  let(:action_count) do
    2
  end

  let(:action_names) do
    action_count.times.collect {
      FactoryGirl.generate :metasploit_model_module_action_name
    }
  end

  let(:default_action_name) do
    action_names.sample
  end

  let(:formatted_actions) do
    action_names.collect { |action_name|
      [
          action_name
      ]
    }
  end

  let(:metasploit_class) do
    default_action_name = self.default_action_name
    formatted_actions = self.formatted_actions

    Class.new(metasploit_super_class) do
      define_method(:initialize) do |info={}|
        super(
            merge_info(
                info,
                'Actions' => formatted_actions,
                'DefaultAction' => default_action_name
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
        actions_length: 0,
        module_class: module_class
    )
  end

  let(:module_type) do
    module_types.sample
  end

  let(:module_types) do
    Metasploit::Model::Module::Instance.module_types_that_allow(:actions)
  end

  context 'CONSTANTS' do
    context 'ALLOW_BY_ATTRIBUTE' do
      subject(:allow_by_attribute) do
        described_class::ALLOW_BY_ATTRIBUTE
      end

      its([:actions]) { should be_true }
    end
  end

  context '#build_added' do
    subject(:build_added) do
      synchronization.build_added
    end

    before(:each) do
      synchronization.should_receive(:added_attributes_set).and_return(added_attributes_set)
    end

    context 'with #added_attributes_set' do
      let(:action_names) do
        2.times.collect {
          FactoryGirl.generate :metasploit_model_module_action_name
        }
      end

      let(:added_attributes_set) do
        Set.new action_names
      end

      it 'should build action for each name' do
        build_added
        actual_module_action_names = module_instance.actions.map(&:name)

        expect(actual_module_action_names).to match_array(action_names)
      end
    end

    context 'without #added_attributes_set' do
      let(:added_attributes_set) do
        Set.new
      end

      it 'should not build any actions' do
        expect {
          build_added
        }.to change(module_instance.actions, :length).by(0)
      end
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

      it { should be_true }
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

      it { should be_false }
    end

    context 'with post' do
      let(:module_type) do
        'post'
      end

      it { should be_true }
    end
  end

  context '#destination_attributes_set' do
    subject(:destination_attributes_set) do
      synchronization.destination_attributes_set
    end

    context 'with new record' do
      it 'should be an empty Set' do
        destination_attributes_set.should == Set.new
      end

      it 'should not query the database' do
        synchronization.should_not_receive(:scope)

        destination_attributes_set
      end
    end

    context 'without new record' do
      let(:action_names) do
        2.times.collect {
          FactoryGirl.generate :metasploit_model_module_action_name
        }
      end

      before(:each) do
        action_names.each do |name|
          module_instance.actions.build(
              name: name
          )
        end

        module_instance.save!
      end

      it 'should contain Mdm::Module::Action#names' do
        expect(destination_attributes_set.to_a).to match_array(action_names)
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
      let(:destination_action_count) do
        arbitrary_maximum = 3
        Random.rand(2 .. arbitrary_maximum)
      end

      let(:destination_action_names) do
        destination_action_count.times.collect {
          FactoryGirl.generate :metasploit_model_module_action_name
        }
      end

      before(:each) do
        destination_action_names.each do |name|
          module_instance.actions.build(
              name: name
          )
        end

        module_instance.save!

        synchronization.stub(removed_attributes_set: removed_attributes_set)
      end

      context 'with removed actions' do
        let(:removed_action_count) do
          Random.rand(1 ... destination_action_names.length)
        end

        let(:removed_action_names) do
          destination_action_names.sample(removed_action_count)
        end

        let(:removed_attributes_set) do
          Set.new removed_action_names
        end

        it 'should destroy Mdm::Module::Actions' do
          expect {
            destroy_removed
          }.to change {
            module_instance.actions.count
          }.by(
                   -1 * removed_action_count
               )
        end
      end

      context 'without removed actions' do
        let(:removed_attributes_set) do
          Set.new
        end

        it 'should not query database' do
          ActiveRecord::Relation.any_instance.should_not_receive(:destroy_all)

          destroy_removed
        end
      end
    end
  end

  context '#source_actions' do
    subject(:source_actions) do
      synchronization.source_actions
    end

    context 'with NoMethodError' do
      #
      # lets
      #

      let(:error) do
        NoMethodError.new("message")
      end

      #
      # callbacks
      #

      before(:each) do
        metasploit_instance.should_receive(:actions).and_raise(error)
      end

      it 'should log module instance error' do
        synchronization.should_receive(:log_module_instance_error).with(module_instance, error)

        source_actions
      end

      it { should == [] }
    end

    context 'without NoMethodError' do
      it 'should return #source actions' do
        source_actions.should == metasploit_instance.actions
      end
    end
  end

  context '#source_attributes_set' do
    subject(:source_attributes_set) do
      synchronization.source_attributes_set
    end

    it 'should use #source_actions instead of source.actions directly' do
      synchronization.should_receive(:source_actions).and_return([])

      source_attributes_set
    end

    it { should be_a Set }

    it 'should include Msf::Module::AuxiliaryAction#names' do
      source_attributes_set.should == Set.new(action_names)
    end
  end

  context 'source_default_action' do
    subject(:source_default_action) do
      synchronization.source_default_action
    end

    context 'with NoMethodError' do
      #
      # lets
      #

      let(:error) do
        NoMethodError.new("message")
      end

      #
      # callbacks
      #

      before(:each) do
        metasploit_instance.should_receive(:default_action).and_raise(error)
      end

      it 'should log module instance error' do
        synchronization.should_receive(:log_module_instance_error).with(module_instance, error)

        source_default_action
      end

      it { should be_nil }
    end

    context 'without NoMethodError' do
      it 'should return #source default_action' do
        source_default_action.should == metasploit_instance.default_action
      end
    end
  end

  context '#synchronize' do
    subject(:synchronize) do
      synchronization.synchronize
    end

    it 'should destroy removed, build added, and update default action' do
      synchronization.should_receive(:destroy_removed).ordered
      synchronization.should_receive(:build_added).ordered
      synchronization.should_receive(:update_default_action).ordered

      synchronize
    end
  end

  context '#update_default_action' do
    subject(:update_default_action) do
      synchronization.update_default_action
    end

    before(:each) do
      synchronization.build_added
    end

    context 'with #source_default_action' do
      it 'should assign action with matching name to #destination #default_action' do
        update_default_action

        module_instance.default_action.should_not be_nil
        module_instance.default_action.name.should == default_action_name
      end
    end

    context 'without #source_default_action' do
      before(:each) do
        synchronization.should_receive(:source_default_action).and_return(nil)
      end

      it 'should not set #destination #default_action' do
        module_instance.should_not_receive(:default_action=)

        update_default_action
      end
    end
  end
end