# -*- coding:binary -*-
require 'msf/base/simple/framework'
require 'metasploit/framework'

shared_context 'Msf::Simple::Framework' do
  include_context 'Metasploit::Framework::Thread::Manager cleaner' do
    let(:thread_manager) do
      # don't create thread manager if example didn't create it
      framework.instance_variable_get :@threads
    end
  end

	let(:framework) do
		Msf::Simple::Framework.create(
				'ConfigDirectory' => framework_config_pathname.to_path,
				# don't load any module paths so we can just load the module under test and save time
				'DeferModuleLoads' => true
		)
	end

	let(:framework_config_pathname) do
    Metasploit::Model::Spec.temporary_pathname.join('framework', 'config')
	end

	before(:each) do
		framework_config_pathname.mkpath
	end

end
