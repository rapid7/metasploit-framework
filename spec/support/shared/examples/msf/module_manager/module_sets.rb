shared_examples_for 'Msf::ModuleManager::ModuleSets' do
	context '#auxiliary' do
		subject(:auxiliary) do
			module_manager.auxiliary
		end

		it 'should call module_set with Metasploit::Model::Module::Type::AUX' do
			module_manager.should_receive(:module_set).with(Metasploit::Model::Module::Type::AUX)

			auxiliary
		end
	end

	context '#encoders' do
		subject(:encoders) do
			module_manager.encoders
		end

		it 'should call module_set with Metasploit::Model::Module::Type::ENCODER' do
			module_manager.should_receive(:module_set).with(Metasploit::Model::Module::Type::ENCODER)

			encoders
		end
	end

	context '#exploits' do
		subject(:exploits) do
			module_manager.exploits
		end

		it 'should call module_set with Metasploit::Model::Module::Type::EXPLOIT' do
			module_manager.should_receive(:module_set).with(Metasploit::Model::Module::Type::EXPLOIT)

			exploits
		end
	end

	context '#nops' do
		subject(:nops) do
			module_manager.nops
		end

		it 'should call module_set with Metasploit::Model::Module::Type::NOP' do
			module_manager.should_receive(:module_set).with(Metasploit::Model::Module::Type::NOP)

			nops
		end
	end

	context '#payloads' do
		subject(:payloads) do
			module_manager.payloads
		end

		it 'should call module_set with Metasploit::Model::Module::Type::PAYLOAD' do
			module_manager.should_receive(:module_set).with(Metasploit::Model::Module::Type::PAYLOAD)

			payloads
		end
	end

	context '#post' do
		subject(:post) do
			module_manager.post
		end

		it 'should call module_set with Metasploit::Model::Module::Type::POST' do
			module_manager.should_receive(:module_set).with(Metasploit::Model::Module::Type::POST)

			post
		end
	end
end