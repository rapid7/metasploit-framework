# -*- coding:binary -*-
require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::Error::MetasploitModuleIncompatibility do
	it { should be_a Metasploit::Framework::Module::Ancestor::Error::Base }

	it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Error#initialize'
end
