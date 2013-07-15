require 'spec_helper'

describe Msf::Payload do
	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::PAYLOAD' do
			type.should == Metasploit::Model::Module::Type::PAYLOAD
		end
	end
end