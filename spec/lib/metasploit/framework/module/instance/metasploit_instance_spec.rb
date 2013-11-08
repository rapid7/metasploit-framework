require 'spec_helper'

describe Metasploit::Framework::Module::Instance::MetasploitInstance do
  include_context 'database seeds'

  subject(:base_instance) do
    base_class.new
  end

  let(:base_class) do
    described_class = self.described_class

    Class.new(Msf::Module) do
      include described_class
    end
  end

  it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache'
end