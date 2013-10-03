# -*- coding:binary -*-
require 'spec_helper'

#
# Core
#

# Temporary files
require 'tempfile'
# add mktmpdir to Dir
require 'tmpdir'

#
# Project
#

require 'msf/core'

describe Msf::ModuleManager do
	include_context 'Msf::Simple::Framework'

  let(:basename_prefix) do
    'rspec'
  end

  subject(:module_manager) do
    framework.modules
  end

  it_should_behave_like 'Msf::ModuleManager::Cache'
  it_should_behave_like 'Msf::ModuleManager::ModulePaths'
	it_should_behave_like 'Msf::ModuleManager::ModuleSets'
end
