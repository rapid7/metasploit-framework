require 'spec_helper'

describe Msf::Nop do
	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::NOP' do
			type.should == Metasploit::Model::Module::Type::NOP
		end
	end
end