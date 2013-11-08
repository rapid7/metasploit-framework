# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core/modules/metasploit_class_compatibility_error'

describe Msf::Modules::MetasploitClassCompatibilityError do
  it_should_behave_like 'Msf::Modules::Error subclass #initialize'
end
