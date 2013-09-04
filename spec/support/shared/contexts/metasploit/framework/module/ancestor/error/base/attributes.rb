# -*- coding:binary -*-
shared_context 'Metasploit::Framework::Module::Ancestor::Error::Base attributes' do
	let(:causal_message) do
		'rspec'
	end

	let(:module_path) do
		"parent/path/type/#{module_reference_name}.rb"
	end

	let(:module_reference_name) do
		'module/reference/name'
	end
end
