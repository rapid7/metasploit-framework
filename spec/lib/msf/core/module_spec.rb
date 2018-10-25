# -*- coding:binary -*-
require 'spec_helper'
require 'msf/core/module'

RSpec.describe Msf::Module do
  subject(:msf_module) {
    described_class.new
  }

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
  it_should_behave_like 'Msf::Module::Search'
  it_should_behave_like 'Msf::Module::Type'
  it_should_behave_like 'Msf::Module::UI'
  it_should_behave_like 'Msf::Module::UUID'

  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :cached? }
    it { is_expected.to respond_to :is_usable }
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
