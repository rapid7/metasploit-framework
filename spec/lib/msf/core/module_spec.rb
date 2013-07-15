require 'spec_helper'

describe Msf::Module do
	context '#type' do
		subject(:type) do
			module_instance.type
		end

		it 'should delegate to class' do
			described_class.should_receive(:type)

			type
		end
	end
end