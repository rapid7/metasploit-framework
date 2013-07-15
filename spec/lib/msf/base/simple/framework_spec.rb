require 'spec_helper'

describe Msf::Simple::Framework do
	include_context 'Msf::Simple::Framework'

	subject do
		framework
	end

	context 'CONSTANTS' do
		context 'ModuleSimplifiers' do
			subject(:module_simplifiers) do
				described_class::ModuleSimplifiers
			end

			it 'should simplify Metasploit::Model::Module::Type::AUX with Msf::Simple::Auxiliary' do
				module_simplifiers[Metasploit::Model::Module::Type::AUX].should == Msf::Simple::Auxiliary
			end

			it 'should simplify Metasploit::Model::Module::Type::ENCODER with Msf::Simple::Encoder' do
				module_simplifiers[Metasploit::Model::Module::Type::ENCODER].should == Msf::Simple::Encoder
			end

			it 'should simplify Metasploit::Model::Module::Type::EXPLOIT with Msf::Simple::Exploit' do
				module_simplifiers[Metasploit::Model::Module::Type::EXPLOIT].should == Msf::Simple::Exploit
			end

			it 'should simplify Metasploit::Model::Module::Type::NOP with Msf::Simple::Nop' do
				module_simplifiers[Metasploit::Model::Module::Type::NOP].should == Msf::Simple::Nop
			end

			it 'should simplify Metasploit::Model::Module::Type::PAYLOAD with Msf::Simple::Payload' do
				module_simplifiers[Metasploit::Model::Module::Type::PAYLOAD].should == Msf::Simple::Payload
			end

			it 'should simplify Metasploit::Model::Module::Type::POST with Msf::Simple::Post' do
				module_simplifiers[Metasploit::Model::Module::Type::POST].should == Msf::Simple::Post
			end
		end
	end

	it_should_behave_like 'Msf::Simple::Framework::ModulePaths'
end