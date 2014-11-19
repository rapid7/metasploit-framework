# -*- coding:binary -*-
require 'spec_helper'
require 'msf/core/module'

describe Msf::Module do
  subject(:msf_module) {
    described_class.new
  }

  it { is_expected.to respond_to :check }
  it { is_expected.to respond_to :debugging? }
  it { is_expected.to respond_to_protected :derived_implementor? }
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
end
