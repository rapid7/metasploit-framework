# -*- coding:binary -*-
require 'msf/base/simple/framework'
require 'metasploit/framework'

shared_context 'Msf::Simple::Framework' do

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

	after(:each) do
		# explicitly kill threads so that they don't exhaust connection pool
		thread_manager = framework.threads

		thread_manager.each do |thread|
			thread.kill
		end

		thread_manager.monitor.kill
	end
end
