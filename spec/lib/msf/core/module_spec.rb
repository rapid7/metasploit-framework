# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Msf::Module do
  subject(:msf_module) {
    described_class.new
  }

  let(:module_with_options) do
    msf_module.instance_eval do
      register_options(
        [
          Msf::Opt::RHOSTS,
          Msf::Opt::RPORT(3000),
        ] + Msf::Opt::stager_retry_options
      )
    end

    msf_module
  end

  it { is_expected.to respond_to :debugging? }
  it { is_expected.to respond_to :fail_with }
  it { is_expected.to respond_to :file_path }
  it { is_expected.to respond_to :framework }
  it { is_expected.to respond_to :orig_cls }
  it { is_expected.to respond_to :owner }
  it { is_expected.to respond_to :platform? }
  it { is_expected.to respond_to :platform_to_s }
  it { is_expected.to respond_to :register_parent }
  it { is_expected.to respond_to :replicant }
  it { is_expected.to respond_to_protected :set_defaults }
  it { is_expected.to respond_to :workspace }

  it_should_behave_like 'Msf::Module::Arch'
  it_should_behave_like 'Msf::Module::Compatibility'
  it_should_behave_like 'Msf::Module::DataStore'
  it_should_behave_like 'Msf::Module::FullName'
  it_should_behave_like 'Msf::Module::ModuleInfo'
  it_should_behave_like 'Msf::Module::ModuleStore'
  it_should_behave_like 'Msf::Module::Network'
  it_should_behave_like 'Msf::Module::Options'
  it_should_behave_like 'Msf::Module::Privileged'
  it_should_behave_like 'Msf::Module::Ranking'
  it_should_behave_like 'Msf::Module::Type'
  it_should_behave_like 'Msf::Module::UI'
  it_should_behave_like 'Msf::Module::UUID'

  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :cached? }
    it { is_expected.to respond_to :usable? }
  end

  describe '#register_options' do
    subject { module_with_options }

    it 'should register the options' do
      expected_options = hash_including(
        {
          'RHOSTS' => an_instance_of(Msf::OptRhosts),
          'RPORT' => an_instance_of(Msf::OptPort),
          'StagerRetryCount' => an_instance_of(Msf::OptInt),
          'StagerRetryWait' => an_instance_of(Msf::OptInt),
        }
      )
      expect(subject.options).to match(expected_options)
    end

    it 'should set defaults on the datastore' do
      expect(subject.datastore['RHOSTS']).to be(nil)
      expect(subject.datastore['RPORT']).to eq(3000)
      expect(subject.datastore['StagerRetryCount']).to eq(10)
      expect(subject.datastore['StagerRetryWait']).to eq(5)
    end
  end

  describe '#deregister_options' do
    subject { module_with_options }

    context 'when the options have previously been registered' do
      before(:each) do
        subject.instance_eval do
          deregister_options('RHOSTS', 'RPORT', 'StagerRetryCount', 'StagerRetryWait')
        end
      end

      it 'should unregister the options' do
        expect(subject.options).to_not have_key('RHOSTS')
        expect(subject.options).to_not have_key('RPORT')
        expect(subject.options).to_not have_key('StagerRetryCount')
        expect(subject.options).to_not have_key('StagerRetryWait')
      end

      it 'should remove the values from the datastore' do
        expect(subject.datastore['RHOSTS']).to be(nil)
        expect(subject.datastore['RPORT']).to be(nil)
        expect(subject.datastore['StagerRetryCount']).to be(nil)
        expect(subject.datastore['StagerRetryWait']).to be(nil)
      end
    end

    context 'when the using an alias to unregister options' do
      before(:each) do
        subject.instance_eval do
          deregister_options(
            # An alias of RHOSTS
            'RHOST',
            'RPORT',
            # An alias of StagerRetryCount
            'ReverseConnectRetries',
            'StagerRetryWait'
          )
        end
      end

      it 'should unregister the options' do
        expect(subject.options).to_not have_key('RHOSTS')
        expect(subject.options).to_not have_key('RPORT')
        expect(subject.options).to_not have_key('StagerRetryCount')
        expect(subject.options).to_not have_key('StagerRetryWait')
      end

      it 'should remove the values from the datastore' do
        expect(subject.datastore['RHOSTS']).to be(nil)
        expect(subject.datastore['RPORT']).to be(nil)
        expect(subject.datastore['StagerRetryCount']).to be(nil)
        expect(subject.datastore['StagerRetryWait']).to be(nil)
      end
    end
  end

  describe "cloning modules into replicants" do
    module MsfExtensionTestFoo; def my_test1; true; end; end;
    module MsfExtensionTestBar; def my_test2; true; end; end;

    describe "#perform_extensions" do
      describe "when there are extensions registered" do
        before(:example) do
          msf_module.register_extensions(MsfExtensionTestFoo, MsfExtensionTestBar)
        end

        it 'should extend the module replicant with the constants referenced in the datastore' do
          expect(msf_module.replicant).to respond_to(:my_test1)
          expect(msf_module.replicant).to respond_to(:my_test2)
        end
      end

      describe "when the datastore key has invalid data" do
        before(:example) do
          msf_module.datastore[Msf::Module::REPLICANT_EXTENSION_DS_KEY] = "invalid"
        end

        it 'should raise an exception' do
          expect{msf_module.replicant}.to raise_error(RuntimeError)
        end
      end
    end

    describe "#register_extensions" do
      describe "with single module" do
        it 'should place the named module in the datastore' do
          msf_module.register_extensions(MsfExtensionTestFoo)
          expect(msf_module.replicant.datastore[Msf::Module::REPLICANT_EXTENSION_DS_KEY]).to eql([MsfExtensionTestFoo])
        end
      end

      describe "with multiple modules" do
        it 'should place the named modules in the datastore' do
          msf_module.register_extensions(MsfExtensionTestFoo, MsfExtensionTestBar)
          expect(msf_module.replicant.datastore[Msf::Module::REPLICANT_EXTENSION_DS_KEY]).to eql([MsfExtensionTestFoo, MsfExtensionTestBar])
        end
      end

    end
  end
end
