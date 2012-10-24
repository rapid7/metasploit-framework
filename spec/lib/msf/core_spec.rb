require 'spec_helper'

require 'msf/core'

describe Msf do
	context 'root' do
		it 'should be the project root' do
			spec_lib_msf_pathname = Pathname.new(__FILE__).dirname
			spec_lib_pathname = spec_lib_msf_pathname.parent
			spec_pathname = spec_lib_pathname.parent
			root_pathname = spec_pathname.parent

			Msf.root.should == root_pathname
		end
	end
end