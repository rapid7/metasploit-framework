require 'spec_helper'

describe Msf::Post do
	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::POST' do
			type.should == Metasploit::Model::Module::Type::POST
		end
	end
end