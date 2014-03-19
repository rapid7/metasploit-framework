# -*- coding:binary -*-
require 'msf/base/simple/framework'
require 'metasploit/framework'

shared_context 'Msf::Simple::Framework' do
  let(:dummy_pathname) do
    Metasploit::Framework.root.join('spec', 'dummy')
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

  before(:each) do
    framework_config_pathname.mkpath
  end

  after(:each) do
    dummy_pathname.rmtree
  end

  after(:each) do
    # explicitly kill threads so that they don't exhaust connection pool
    thread_manager = framework.threads

    thread_manager.each do |thread|
      thread.kill
      # join after kill to ensure kill completed and thread is removed form Thread.list
      thread.join
    end

    thread_manager.monitor.kill
    # join after kill to ensure kill completed and thread is removed form Thread.list
    thread_manager.monitor.join
  end
end
