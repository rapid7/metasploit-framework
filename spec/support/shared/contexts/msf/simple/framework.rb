# -*- coding:binary -*-
require 'metasploit/framework'

RSpec.shared_context 'Msf::Simple::Framework' do
  let(:dummy_pathname) do
    Rails.root.join('spec', 'dummy')
  end

  let(:framework) do
    Msf::Simple::Framework.create(
        'ConfigDirectory' => framework_config_pathname.to_s,
        # don't load any module paths so we can just load the module under test and save time
        'DeferModuleLoads' => true
    )
  end

  let(:framework_config_pathname) do
    dummy_pathname.join('framework', 'config')
  end

  before(:example) do
    framework_config_pathname.mkpath
  end

  after(:example) do
    FileUtils.rm_rf(dummy_pathname)
  end
end
