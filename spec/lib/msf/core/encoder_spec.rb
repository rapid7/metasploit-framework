require 'spec_helper'

describe Msf::Encoder do
	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::ENCODER' do
			type.should == Metasploit::Model::Module::Type::ENCODER
		end
	end
end