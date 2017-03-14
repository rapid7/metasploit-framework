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

RSpec.describe Msf::ModuleManager do
  include_context 'Msf::Simple::Framework'

  let(:basename_prefix) do
    'rspec'
  end

  subject(:module_manager) do
    framework.modules
  end

  it_should_behave_like 'Msf::ModuleManager::Cache'
  it_should_behave_like 'Msf::ModuleManager::Loading'
  it_should_behave_like 'Msf::ModuleManager::ModulePaths'
end
