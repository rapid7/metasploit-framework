# -*- coding: binary -*-

require 'rex/encoding/xor/byte'
require 'spec_helper'

describe Rex::Encoding::Xor::Byte do
	it_behaves_like "an xor encoder", 1
end
