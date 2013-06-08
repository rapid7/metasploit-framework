# -*- coding: binary -*-

require 'rex/encoding/xor/word'
require 'spec_helper'

describe Rex::Encoding::Xor::Word do
	it_behaves_like "an xor encoder", 2
end
