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
  it_should_behave_like 'Msf::ModuleManager::Loading'
  it_should_behave_like 'Msf::ModuleManager::ModulePaths'
	it_should_behave_like 'Msf::ModuleManager::ModuleSets'

	context '#initialize' do
		it 'should call init_module_set with all module types by default' do
      Metasploit::Model::Module::Type::ALL.each do |module_type|
				described_class.any_instance.should_receive(:init_module_set).with(module_type)
			end

			framework
		end
	end
end
