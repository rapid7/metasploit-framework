require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::MetasploitModule do
  include_context 'database seeds'

  subject(:metasploit_module) do
    described_class = self.described_class
    rank = self.rank

    Module.new {
      extend described_class
    }.tap { |m|
      m.define_singleton_method(:rank_name) do
        rank.name
      end
    }
  end

  let(:module_class) do
    with_established_connection do
      FactoryGirl.build(
          :mdm_module_class,
          # nil rank as #cache is expected to set rank
          rank: nil
      )
    end
  end

  let(:rank) do
    with_established_connection {
      FactoryGirl.generate :mdm_module_rank
    }
  end

  it_should_behave_like 'Metasploit::Framework::ProxiedValidation' do
    let(:target) do
      metasploit_module
    end
  end

  context 'validations' do
    context 'usable' do
      context 'default' do
        it { should be_valid }
      end

      context 'with is_usable false' do
        let(:error) do
          I18n.translate('activemodel.errors.models.metasploit/framework/module/ancestor/metasploit_module.attributes.base.unusable')
        end

        before(:each) do
          metasploit_module.module_eval do
            def self.is_usable
              false
            end
          end
        end

        it { should_not be_valid }

        it 'should add error on :base' do
          metasploit_module.valid?

          metasploit_module.errors[:base].should include(error)
        end
      end
    end
  end

  context '#cache' do
    subject(:cache) do
      with_established_connection {
        metasploit_module.cache(module_class)
      }
    end

    context 'with error in cache_rank' do
      before(:each) do
        metasploit_module.stub(:rank_name).and_raise(NoMethodError)
      end

      it 'should not raise error' do
        expect {
          cache
        }.to_not raise_error
      end

      it 'should not create Mdm::Module::Class' do
        expect {
          cache
        }.to_not change {
          with_established_connection {
            Mdm::Module::Class.count
          }
        }
      end
    end

    context 'without error in cache_rank' do
      it 'should call #cache_rank' do
        metasploit_module.should_receive(:cache_rank).with(module_class).and_call_original

        cache
      end

      it 'should create Mdm::Module::Class' do
        expect {
          cache
        }.to change {
          with_established_connection {
            Mdm::Module::Class.count
          }
        }.by(1)
      end

      context 'Mdm::Module::Class' do
        subject do
          module_class
        end

        before(:each) do
          cache
        end

        it 'should have rank with same name as #rank_name' do
          module_class.rank.name.should == metasploit_module.rank_name
        end
      end
    end
  end

  context '#cache_rank' do
    subject(:cache_rank) do
      with_established_connection {
        metasploit_module.cache_rank(module_class)
      }
    end

    context 'with error in rank_name' do
      before(:each) do
        metasploit_module.stub(:rank_name).and_raise(NoMethodError)
      end

      it 'should not raise exception' do
        expect {
          cache_rank
        }.to_not raise_error
      end
    end

    context 'without error in rank_name' do
      it 'should set module_class.rank' do
        expect {
          cache_rank
        }.to change {
          module_class.rank
        }.to(rank)
      end
    end
  end

  context '#is_usable' do
    subject(:is_usable) do
      metasploit_module.is_usable
    end

    it { should be_true }
  end

  context '#validation_proxy_class' do
    subject(:validation_proxy_class) do
      metasploit_module.validation_proxy_class
    end

    it { should == Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy }
  end
end