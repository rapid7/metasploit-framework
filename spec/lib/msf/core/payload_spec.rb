require 'spec_helper'

describe Msf::Payload do
  it 'should extend Metasploit::Framework::Module::Class::Handler' do
    described_class.should be_a Metasploit::Framework::Module::Class::Handler
  end

	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::PAYLOAD' do
			type.should == Metasploit::Model::Module::Type::PAYLOAD
		end
	end
end