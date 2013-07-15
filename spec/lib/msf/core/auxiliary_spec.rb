require 'spec_helper'

describe Msf::Auxiliary do
	subject(:auxiliary) do
		described_class.new
	end

	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::AUX' do
			type.should == Metasploit::Model::Module::Type::AUX
		end
	end
end