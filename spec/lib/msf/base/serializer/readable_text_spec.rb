require 'spec_helper'

describe Msf::Serializer::ReadableText do
	context 'dump_module' do
		subject(:dump_module) do
			described_class.dump_module(module_instance)
		end

		let(:indent) do
			'  '
		end

		let(:module_instance) do
			double('Msf::Module', :type => type)
		end

		context 'with Metasploit::Model::Module::Type::AUX' do
			let(:type) do
				Metasploit::Model::Module::Type::AUX
			end

			it 'should call dump_auxiliary_module' do
				described_class.should_receive(:dump_auxiliary_module).with(module_instance, indent)

				dump_module
			end
		end

		context 'with Metasploit::Model::Module::Type::ENCODER' do
			let(:type) do
				Metasploit::Model::Module::Type::ENCODER
			end

			it 'should call dump_basic_module' do
				described_class.should_receive(:dump_basic_module).with(module_instance, indent)

				dump_module
			end
		end

		context 'with Metasploit::Model::Module::Type::EXPLOIT' do
			let(:type) do
				Metasploit::Model::Module::Type::EXPLOIT
			end

			it 'should call dump_exploit_module' do
				described_class.should_receive(:dump_exploit_module).with(module_instance, indent)

				dump_module
			end
		end

		context 'with Metasploit::Model::Module::Type::NOP' do
			let(:type) do
				Metasploit::Model::Module::Type::NOP
			end

			it 'should call dump_basic_module' do
				described_class.should_receive(:dump_basic_module).with(module_instance, indent)

				dump_module
			end
		end

		context 'with Metasploit::Model::Module::Type::PAYLOAD' do
			let(:type) do
				Metasploit::Model::Module::Type::PAYLOAD
			end

			it 'should call dump_payload_module' do
				described_class.should_receive(:dump_payload_module).with(module_instance, indent)

				dump_module
			end
		end

		context 'with Metasploit::Model::Module::Type::POST' do
			let(:type) do
				Metasploit::Model::Module::Type::POST
			end

			it 'should call dump_basic_module' do
				described_class.should_receive(:dump_basic_module).with(module_instance, indent)

				dump_module
			end
		end

		context 'with unrecognized module type' do
			let(:type) do
				'unrecognized module type'
			end

			it 'should call dump_generic_module' do
				described_class.should_receive(:dump_generic_module).with(module_instance, indent)

				dump_module
			end
		end
	end
end