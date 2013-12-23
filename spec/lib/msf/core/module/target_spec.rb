require 'spec_helper'

describe Msf::Module::Target do
  subject(:target) do
    described_class.new(name, options)
  end

  let(:name) do
    FactoryGirl.generate :metasploit_model_module_target_name
  end

  let(:options) do
    {}
  end

  it_should_behave_like 'Msf::Module::Target::Platforms'
end