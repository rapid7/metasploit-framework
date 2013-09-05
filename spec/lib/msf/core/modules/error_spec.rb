# -*- coding:binary -*-
require 'spec_helper'

describe Msf::Modules::Error do
	context 'instance methods' do
		context '#initialize' do
      include_context 'Msf::Modules::Error attributes'

			context 'with :causal_message' do
				subject do
					described_class.new(:causal_message => causal_message)
				end

				it 'should include causal_message in error' do
					subject.to_s.should == "Failed to load module due to #{causal_message}"
				end
			end

			context 'with :causal_message and :module_path' do
				subject do
					described_class.new(
							:causal_message => causal_message,
							:module_path => module_path
					)
				end

				it 'should include causal_message and module_path in error' do
					subject.to_s.should == "Failed to load module (from #{module_path}) due to #{causal_message}"
				end
			end

			context 'with :causal_message and :module_reference_name' do
        subject do
	        described_class.new(
			        :causal_message => causal_message,
	            :module_reference_name => module_reference_name
	        )
        end

				it 'should include causal_message and module_reference_name in error' do
					subject.to_s.should == "Failed to load module (#{module_reference_name}) due to #{causal_message}"
				end
			end

			context 'with :causal_message, :module_path, and :module_reference_nam' do
				subject do
					described_class.new(
							:causal_message => causal_message,
					    :module_path => module_path,
					    :module_reference_name => module_reference_name
					)
				end

				it 'should include causal_message, module_path, and module_reference_name in error' do
					subject.to_s.should == "Failed to load module (#{module_reference_name} from #{module_path}) due to #{causal_message}"
				end
			end

			context 'with :module_path' do
				subject do
					described_class.new(:module_path => module_path)
				end

				it 'should use :module_path for module_path' do
					subject.module_path.should == module_path
				end

				it 'should include module_path in error' do
					subject.to_s.should == "Failed to load module (from #{module_path})"
				end
			end

			context 'with :module_path and :module_reference_name' do
				subject do
					described_class.new(
							:module_path => module_path,
							:module_reference_name => module_reference_name
					)
				end

				it 'should include module_path and module_reference_name in error' do
					subject.to_s.should == "Failed to load module (#{module_reference_name} from #{module_path})"
				end
			end

			context 'with :module_reference_name' do
				subject do
					described_class.new(:module_reference_name => module_reference_name)
				end

				it 'should use :module_reference_name for module_reference_name' do
					subject.module_reference_name.should == module_reference_name
				end

				it 'should include module_reference_name in error' do
					subject.to_s.should == "Failed to load module (#{module_reference_name})"
				end
			end

		end
	end
end
