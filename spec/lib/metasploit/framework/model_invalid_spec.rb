require 'spec_helper'

describe Metasploit::Framework::ModelInvalid do
	let(:model) do
		model_class.new
	end

	let(:model_class) do
		Class.new do
			include ActiveModel::Validations

			#
			# Methods
			#

			# Name of model.  Used in error reporting.
			#
			# @return [ActivModel::Name]
			def self.model_name
				ActiveModel::Name.new(self, Metasploit::Framework, 'Model')
			end
		end
	end

  context '#initialize' do
		subject(:initialize) do
			described_class.new(model)
		end

		it 'should take an ActiveModel' do
			expect {
				initialize
			}.to_not raise_error
		end

		it 'should translate the using metasploit.framework.errors.messages.model_invalid' do
			I18n.should_receive(:translate!).with(
					'metasploit.framework.errors.messages.model_invalid',
					hash_including(
							:errors => anything
					)
			).and_call_original

			initialize
		end
	end
end