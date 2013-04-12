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
  let(:archive_basename) do
    [basename_prefix, archive_extension]
  end

  let(:archive_extension) do
    '.fastlib'
  end

  let(:basename_prefix) do
    'rspec'
  end

  let(:framework) do
    Msf::Framework.new
  end

  subject(:module_manager) do
    described_class.new(framework)
  end

  it_should_behave_like 'Msf::ModuleManager::Loading'
  it_should_behave_like 'Msf::ModuleManager::ModulePaths'
end