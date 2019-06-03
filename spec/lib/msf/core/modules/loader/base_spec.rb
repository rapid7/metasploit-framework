# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'

RSpec.describe Msf::Modules::Loader::Base do
  include_context 'Msf::Modules::Loader::Base'

  let(:described_class_pathname) do
    root_pathname.join('lib', 'msf', 'core', 'modules', 'loader', 'base.rb')
  end

  let(:malformed_module_content) do
    <<-EOS
      class Metasploit
        # purposeful typo to check that module path is used in backtrace
        inclde Exploit::Remote::Tcp
      end
    EOS
  end

  let(:module_content) do
    <<-EOS
      class MetasploitModule < Msf::Auxiliary
        # fully-qualified name is Msf::GoodRanking, so this will failing if lexical scope is not captured
        Rank = GoodRanking
        end
    EOS
  end

  let(:module_full_name) do
    "#{type}/#{module_reference_name}"
  end

  let(:module_path) do
    parent_pathname.join('auxiliary', 'rspec', 'mock.rb').to_s
  end

  let(:module_reference_name) do
    'rspec/mock'
  end

  let(:type) do
    Msf::MODULE_AUX
  end

  context 'CONSTANTS' do

    context 'DIRECTORY_BY_TYPE' do
      let(:directory_by_type) do
        described_class::DIRECTORY_BY_TYPE
      end

      it 'should be defined' do
        expect(described_class.const_defined?(:DIRECTORY_BY_TYPE)).to be_truthy
      end

      it 'should map Msf::MODULE_AUX to auxiliary' do
        expect(directory_by_type[Msf::MODULE_AUX]).to eq 'auxiliary'
      end

      it 'should map Msf::MODULE_ENCODER to encoders' do
        expect(directory_by_type[Msf::MODULE_ENCODER]).to eq 'encoders'
      end

      it 'should map Msf::MODULE_EXPLOIT to exploits' do
        expect(directory_by_type[Msf::MODULE_EXPLOIT]).to eq 'exploits'
      end

      it 'should map Msf::MODULE_NOP to nops' do
        expect(directory_by_type[Msf::MODULE_NOP]).to eq 'nops'
      end

      it 'should map Msf::MODULE_PAYLOAD to payloads' do
        expect(directory_by_type[Msf::MODULE_PAYLOAD]).to eq 'payloads'
      end

      it 'should map Msf::MODULE_POST to post' do
        expect(directory_by_type[Msf::MODULE_POST]).to eq 'post'
      end
    end

    context 'NAMESPACE_MODULE_LINE' do
      it 'should be line number for first line of NAMESPACE_MODULE_CONTENT' do
        file_lines = []

        described_class_pathname.open do |f|
          file_lines = f.to_a
        end

        # -1 because file lines are 1-based, but array is 0-based
        file_line = file_lines[described_class::NAMESPACE_MODULE_LINE - 1]

        constant_lines = described_class::NAMESPACE_MODULE_CONTENT.lines.to_a
        constant_line = constant_lines.first

        expect(file_line).to eq constant_line
      end
    end

    context 'NAMESPACE_MODULE_CONTENT' do
      context 'derived module' do
        include_context 'Metasploit::Framework::Spec::Constants cleaner'

        let(:namespace_module_names) do
          ['Msf', 'Modules', 'Auxiliary__Rspec__Mock']
        end

        let(:namespace_module) do
          Object.module_eval(
              <<-EOS
              module #{namespace_module_names[0]}
                module #{namespace_module_names[1]}
                  module #{namespace_module_names[2]}
                    #{described_class::NAMESPACE_MODULE_CONTENT}
                  end
                end
              end
          EOS
          )

          namespace_module_names.join('::').constantize
        end

        context 'loader' do
          it 'should be a read/write attribute' do
            loader = double('Loader')
            namespace_module.loader = loader

            expect(namespace_module.loader).to eq loader
          end
        end

        context 'module_eval_with_lexical_scope' do
          it 'should capture the lexical scope' do
            expect {
              namespace_module.module_eval_with_lexical_scope(module_content, module_path)
            }.to_not raise_error
          end

          context 'with malformed module content' do
            it 'should use module path in module_eval' do
              error = nil

              begin
                namespace_module.module_eval_with_lexical_scope(malformed_module_content, module_path)
              rescue NoMethodError => error
                # don't put the should in the rescue because if there is no error, then the example will still be
                # successful.
              end

              expect(error).not_to be_nil
              expect(error.backtrace[0]).to include(module_path)
            end
          end
        end

        context 'parent_path' do
          it 'should be a read/write attribute' do
            parent_path = double('Parent Path')
            namespace_module.parent_path = parent_path

            expect(namespace_module.parent_path).to eq parent_path
          end
        end
      end
    end

    context 'MODULE_EXTENSION' do
      it 'should only support ruby source modules' do
        expect(described_class::MODULE_EXTENSION).to eq '.rb'
      end
    end

    context 'MODULE_SEPARATOR' do
      it 'should make valid module names' do
        name = ['Msf', 'Modules'].join(described_class::MODULE_SEPARATOR)
        expect(name.constantize).to eq Msf::Modules
      end
    end

    context 'NAMESPACE_MODULE_NAMES' do
      it 'should be under Msf so that Msf constants resolve from lexical scope' do
        expect(described_class::NAMESPACE_MODULE_NAMES).to include('Msf')
      end

      it "should not be directly under Msf so that modules don't collide with core namespaces" do
        direct_index = described_class::NAMESPACE_MODULE_NAMES.index('Msf')
        last_index = described_class::NAMESPACE_MODULE_NAMES.length - 1

        expect(last_index).to be > direct_index
      end
    end

    context 'UNIT_TEST_REGEX' do
      it 'should match test suite files' do
        expect(described_class::UNIT_TEST_REGEX).to match('rb.ts.rb')
      end

      it 'should match unit test files' do
        expect(described_class::UNIT_TEST_REGEX).to match('rb.ut.rb')
      end
    end
  end

  context 'class methods' do
    context 'typed_path' do
      it 'should have MODULE_EXTENSION for the extension name' do
        typed_path = described_class.typed_path(Msf::MODULE_AUX, module_reference_name)

        expect(File.extname(typed_path)).to eq described_class::MODULE_EXTENSION
      end

      # Don't iterate over a Hash here as that would too closely mirror the actual implementation and not test anything
      it_should_behave_like 'typed_path', 'Msf::MODULE_AUX' => 'auxiliary'
      it_should_behave_like 'typed_path', 'Msf::MODULE_ENCODER' => 'encoders'
      it_should_behave_like 'typed_path', 'Msf::MODULE_EXPLOIT' => 'exploits'
      it_should_behave_like 'typed_path', 'Msf::MODULE_NOP' => 'nops'
      it_should_behave_like 'typed_path', 'Msf::MODULE_PAYLOAD' => 'payloads'
      it_should_behave_like 'typed_path', 'Msf::MODULE_POST' => 'post'
    end
  end

  context 'instance methods' do
    let(:module_manager) do
      double('Module Manager', :module_load_error_by_path => {}, :module_load_warnings => {})
    end

    subject do
      described_class.new(module_manager)
    end

    context '#initialize' do
      it 'should set @module_manager' do
        loader = described_class.new(module_manager)
        expect(loader.instance_variable_get(:@module_manager)).to eq module_manager
      end
    end

    context '#loadable?' do
      it 'should be abstract' do
        expect {
          subject.loadable?(parent_pathname.to_s)
        }.to raise_error(NotImplementedError)
      end
    end

    context '#load_module' do
      let(:parent_path) do
        parent_pathname.to_s
      end

      let(:type) do
        Msf::MODULE_AUX
      end

      before(:example) do
        allow(subject).to receive(:module_path).and_return(module_path)
      end

      it 'should call file_changed? with the module_path' do
        expect(module_manager).to receive(:file_changed?).with(module_path).and_return(false)

        subject.load_module(parent_path, type, module_reference_name, :force => false)
      end

      context 'without file changed' do
        before(:example) do
          allow(module_manager).to receive(:file_changed?).and_return(false)
        end

        it 'should return false if :force is false' do
          expect(subject.load_module(parent_path, type, module_reference_name, :force => false)).to be_falsey
        end

        it 'should not call #read_module_content' do
          expect(subject).not_to receive(:read_module_content)
          subject.load_module(parent_path, type, module_reference_name)
        end
      end

      context 'with file changed' do
        include_context 'Metasploit::Framework::Spec::Constants cleaner'

        let(:module_full_name) do
          File.join('auxiliary', module_reference_name)
        end

        let(:namespace_module) do
          Msf::Modules.const_get(relative_name)
        end

        let(:relative_name) do
          'Auxiliary__Rspec__Mock'
        end

        before(:example) do
          # capture in a local so that instance_eval can access it
          relative_name = self.relative_name

          # remove module from previous examples so reload error aren't logged
          if Msf::Modules.const_defined? relative_name
            Msf::Modules.instance_eval do
              remove_const relative_name
            end
          end

          # create an namespace module that can be restored
          module Msf
            module Modules
              module Auxiliary__Rspec__Mock
                class MetasploitModule < Msf::Auxiliary

                end
              end
            end
          end

          @original_namespace_module = Msf::Modules::Auxiliary__Rspec__Mock

          module_set = double('Module Set')
          allow(module_set).to receive(:delete).with(module_reference_name)

          allow(module_manager).to receive(:delete).with(module_reference_name)
          allow(module_manager).to receive(:file_changed?).with(module_path).and_return(true)
          allow(module_manager).to receive(:module_set).with(type).and_return(module_set)
        end

        it 'should call #namespace_module_transaction with the module full name and :reload => true' do
          allow(subject).to receive(:read_module_content).and_return(module_content)

          expect(subject).to receive(:namespace_module_transaction).with(module_full_name, hash_including(:reload => true))

          subject.load_module(parent_path, type, module_reference_name)
        end

        it 'should set the parent_path on the namespace_module to match the parent_path passed to #load_module' do
          allow(module_manager).to receive(:on_module_load)

          allow(subject).to receive(:read_module_content).and_return(module_content)

          expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy

          expect(namespace_module.parent_path).to eq parent_path
        end

        it 'should call #read_module_content to get the module content so that #read_module_content can be overridden to change loading behavior' do
          allow(module_manager).to receive(:on_module_load)

          expect(subject).to receive(:read_module_content).with(parent_path, type, module_reference_name).and_return(module_content)

          expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy
        end

        it 'should call namespace_module.module_eval_with_lexical_scope with the module_path' do
          allow(subject).to receive(:read_module_content).and_return(malformed_module_content)
          allow(module_manager).to receive(:on_module_load)

          # if the module eval error includes the module_path then the module_path was passed along correctly
          expect(subject).to receive(:elog).with(/#{Regexp.escape(module_path)}/)
          expect(subject.load_module(parent_path, type, module_reference_name, :reload => true)).to be_falsey
        end

        context 'with empty module content' do
          before(:example) do
            allow(subject).to receive(:read_module_content).with(parent_path, type, module_reference_name).and_return('')
          end

          it 'should return false' do
            expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
          end

          it 'should not attempt to make a new namespace_module' do
            expect(subject).not_to receive(:namespace_module_transaction)
            expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
          end
        end

        context 'with errors from namespace_module_eval_with_lexical_scope' do
          before(:example) do
            @namespace_module = double('Namespace Module', :'parent_path=' => nil)
            module_content = double('Module Content', empty?: false)

            allow(subject).to receive(:namespace_module_transaction).and_yield(@namespace_module)
            allow(subject).to receive(:read_module_content).and_return(module_content)
          end

          context 'with Interrupt' do
            it 'should re-raise' do
              allow(@namespace_module).to receive(:module_eval_with_lexical_scope).and_raise(Interrupt)

              expect {
                subject.load_module(parent_path, type, module_reference_name)
              }.to raise_error(Interrupt)
            end
          end

          context 'with other Exception' do
            let(:backtrace) do
              [
                'Backtrace Line 1',
                'Backtrace Line 2'
              ]
            end

            let(:error) do
              error_class.new(error_message)
            end

            let(:error_class) do
              ArgumentError
            end

            let(:error_message) do
              'This is rspec.  Your argument is invalid.'
            end

            before(:example) do
              allow(@namespace_module).to receive(:module_eval_with_lexical_scope).and_raise(error)

              @module_load_error_by_path = {}
              allow(module_manager).to receive(:module_load_error_by_path).and_return(@module_load_error_by_path)

              allow(error).to receive(:backtrace).and_return(backtrace)
            end

            it 'should record the load error using the original error' do
              expect(subject).to receive(:load_error).with(module_path, error)
              expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
            end

            it 'should return false' do
              expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
            end
          end
        end

        context 'without module_eval errors' do
          before(:example) do
            @namespace_module = double('Namespace Module')
            allow(@namespace_module).to receive(:parent_path=)
            allow(@namespace_module).to receive(:module_eval_with_lexical_scope).with(module_content, module_path)
            allow(@namespace_module).to receive(:const_defined?).with('Metasploit3', false).and_return(false)
            allow(@namespace_module).to receive(:const_defined?).with('Metasploit4', false).and_return(false)
            allow(@namespace_module).to receive(:const_defined?).with('MetasploitModule', false).and_return(true)
            allow(@namespace_module).to receive(:const_get).with('Metasploit3', false).and_return(false)
            allow(@namespace_module).to receive(:const_get).with('Metasploit4', false).and_return(false)
            allow(@namespace_module).to receive(:const_get).with('MetasploitModule', false).and_return(true)
            allow(@namespace_module).to receive(:module_load_warnings)

            allow(subject).to receive(:namespace_module_transaction).and_yield(@namespace_module)

            allow(subject).to receive(:read_module_content).with(parent_path, type, module_reference_name).and_return(module_content)

            @module_load_error_by_path = {}
            allow(module_manager).to receive(:module_load_error_by_path).and_return(@module_load_error_by_path)
            allow(module_manager).to receive(:on_module_load)
            # remove the mocked namespace_module since happy-path/real loading is occurring in this context
            allow(subject).to receive(:namespace_module_transaction).and_call_original
          end

          it 'should log load information' do
            expect(subject).to receive(:ilog).with(/#{module_reference_name}/, 'core', LEV_2)
            expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy
          end

          it 'should delete any pre-existing load errors from module_manager.module_load_error_by_path' do
            original_load_error = "Back in my day this module didn't load"
            module_manager.module_load_error_by_path[module_path] = original_load_error

            expect(module_manager.module_load_error_by_path[module_path]).to eq original_load_error
            expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy
            expect(module_manager.module_load_error_by_path[module_path]).to be_nil
          end

          it 'should return true' do
            expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy
          end

          it 'should call module_manager.on_module_load' do
            expect(module_manager).to receive(:on_module_load)
            expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy
          end

          context 'with :recalculate_by_type' do
            it 'should set the type to be recalculated' do
              recalculate_by_type = {}

              expect(
                subject.load_module(
                  parent_path,
                  type,
                  module_reference_name,
                  :recalculate_by_type => recalculate_by_type
                )
              ).to eq true
              expect(recalculate_by_type[type]).to be_truthy
            end
          end

          context 'with :count_by_type' do
            it 'should set the count to 1 if it does not exist' do
              count_by_type = {}

              expect(count_by_type.has_key?(type)).to be_falsey
              expect(
                subject.load_module(
                  parent_path,
                  type,
                  module_reference_name,
                  :count_by_type => count_by_type
                )
              ).to eq true
              expect(count_by_type[type]).to eq 1
            end

            it 'should increment the count if it does exist' do
              original_count = 1
              count_by_type = {
                  type => original_count
              }

              expect(
                subject.load_module(
                  parent_path,
                  type,
                  module_reference_name,
                  :count_by_type => count_by_type
                )
              ).to eq true

              incremented_count = original_count + 1
              expect(count_by_type[type]).to eq incremented_count
            end
          end
        end
      end
    end

    context '#create_namespace_module' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      let(:namespace_module_names) do
        [
            'Msf',
            'Modules',
            relative_name
        ]
      end

      let(:relative_name) do
        'Auxiliary__Rspec__Mock'
      end

      before(:example) do
        # capture in local variable so it works in instance_eval
        relative_name = self.relative_name

        if Msf::Modules.const_defined? relative_name
          Msf::Modules.instance_eval do
            remove_const relative_name
          end
        end
      end

      it 'should wrap NAMESPACE_MODULE_CONTENT with module declarations matching namespace_module_names' do
        expect(Object).to receive(
            :module_eval
        ).with(
            "module #{namespace_module_names[0]}\n" \
            "module #{namespace_module_names[1]}\n" \
            "module #{namespace_module_names[2]}\n" \
            "#{described_class::NAMESPACE_MODULE_CONTENT}\n" \
            "end\n" \
            "end\n" \
            "end",
            anything,
            anything
        )

        namespace_module = double('Namespace Module')
        expect(namespace_module).to receive(:loader=)
        expect(subject).to receive(:current_module).and_return(namespace_module)

        subject.send(:create_namespace_module, namespace_module_names)
      end

      it "should set the module_eval path to the loader's __FILE__" do
        expect(Object).to receive(
            :module_eval
        ).with(
            anything,
            described_class_pathname.to_s,
            anything
        )

        namespace_module = double('Namespace Module')
        expect(namespace_module).to receive(:loader=)
        expect(subject).to receive(:current_module).and_return(namespace_module)

        subject.send(:create_namespace_module, namespace_module_names)
      end

      it 'should set the module_eval line to compensate for the wrapping module declarations' do
        expect(Object).to receive(
            :module_eval
        ).with(
            anything,
            anything,
            described_class::NAMESPACE_MODULE_LINE - namespace_module_names.length
        )

        namespace_module = double('Namespace Module')
        expect(namespace_module).to receive(:loader=)
        expect(subject).to receive(:current_module).and_return(namespace_module)

        subject.send(:create_namespace_module, namespace_module_names)
      end

      it "should set the namespace_module's module loader to itself" do
        namespace_module = double('Namespace Module')

        expect(namespace_module).to receive(:loader=).with(subject)

        expect(subject).to receive(:current_module).and_return(namespace_module)

        subject.send(:create_namespace_module, namespace_module_names)
      end
    end

    context '#current_module' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      let(:module_names) do
        [
            'Msf',
            'Modules',
            relative_name
        ]
      end

      let(:relative_name) do
        'Auxiliary__Rspec__Mock'
      end

      before(:example) do
        # copy to local variable so it is accessible in instance_eval
        relative_name = self.relative_name

        if Msf::Modules.const_defined? relative_name
          Msf::Modules.instance_eval do
            remove_const relative_name
          end
        end
      end

      it 'should return nil if the module is not defined' do
        expect(Msf::Modules.const_defined?(relative_name)).to be_falsey
        expect(subject.send(:current_module, module_names)).to be_nil
      end

      it 'should return the module if it is defined' do
        module Msf
          module Modules
            module Auxiliary__Rspec__Mock
            end
          end
        end

        expect(subject.send(:current_module, module_names)).to eq Msf::Modules::Auxiliary__Rspec__Mock
      end
    end

    context '#each_module_reference_name' do
      it 'should be abstract' do
        expect {
          subject.send(:each_module_reference_name, parent_path)
        }.to raise_error(NotImplementedError)
      end
    end

    context '#module_path' do
      it 'should be abstract' do
        expect {
          subject.send(:module_path, parent_path, Msf::MODULE_AUX, module_reference_name)
        }.to raise_error(NotImplementedError)
      end
    end

    context '#module_path?' do
      it 'should return false if path is hidden' do
        hidden_path = '.hidden/path/file.rb'

        expect(subject.send(:module_path?, hidden_path)).to be_falsey
      end

      it 'should return false if the file extension is not MODULE_EXTENSION' do
        non_module_extension = '.c'
        path = "path/with/wrong/extension#{non_module_extension}"

        expect(non_module_extension).not_to eq described_class::MODULE_EXTENSION
        expect(subject.send(:module_path?, path)).to be_falsey
      end

      it 'should return false if the file is a unit test' do
        unit_test_extension = '.rb.ut.rb'
        path = "path/to/unit_test#{unit_test_extension}"

        expect(subject.send(:module_path?, path)).to be_falsey
      end

      it 'should return false if the file is a test suite' do
        test_suite_extension = '.rb.ts.rb'
        path = "path/to/test_suite#{test_suite_extension}"

        expect(subject.send(:module_path?, path)).to be_falsey
      end

      it 'should return true otherwise' do
        expect(subject.send(:module_path?, module_path)).to be_truthy
      end
    end

    context '#module_reference_name_from_path' do
      it 'should strip MODULE_EXTENSION from the end of the path' do
        path_without_extension = "a#{described_class::MODULE_EXTENSION}.dir/a"
        path = "#{path_without_extension}#{described_class::MODULE_EXTENSION}"

        expect(subject.send(:module_reference_name_from_path, path)).to eq path_without_extension
      end
    end

    context '#namespace_module_name' do
      it 'should prefix the name with Msf::Modules::' do
        expect(subject.send(:namespace_module_name, module_full_name)).to start_with('Msf::Modules::')
      end

      it 'should be reversible' do
        namespace_module_name = subject.send(:namespace_module_name, module_full_name)
        relative_name = namespace_module_name.gsub(/^.*::/, '')
        reversed_name = described_class.reverse_relative_name(relative_name)

        expect(reversed_name).to eq module_full_name
      end
    end

    context '#namespace_module_names' do
      it "should prefix the array with ['Msf', 'Modules']" do
        expect(subject.send(:namespace_module_names, module_full_name)).to start_with(['Msf', 'Modules'])
      end

      it 'should be reversible' do
        namespace_module_names = subject.send(:namespace_module_names, module_full_name)
        relative_name = namespace_module_names.last
        reversed_name = described_class.reverse_relative_name(relative_name)

        expect(reversed_name).to eq module_full_name
      end
    end

    context '#namespace_module_transaction' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      let(:relative_name) do
        'Auxiliary__Rspec__Mock'
      end

      context 'with pre-existing namespace module' do
        before(:example) do
          module Msf
            module Modules
              module Auxiliary__Rspec__Mock
                class Metasploit

                end
              end
            end
          end

          @existent_namespace_module = Msf::Modules::Auxiliary__Rspec__Mock
        end

        context 'with :reload => false' do
          it 'should log an error' do
            expect(subject).to receive(:elog).with(/Reloading.*when :reload => false/)

            subject.send(:namespace_module_transaction, module_full_name, :reload => false) do |namespace_module|
              true
            end
          end
        end

        it 'should remove the pre-existing namespace module' do
          expect(Msf::Modules).to receive(:remove_const).with(relative_name.to_sym).and_call_original
          expect(Msf::Modules).to receive(:remove_const).with(relative_name).and_call_original

          subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
            true
          end
        end

        it 'should create a new namespace module for the block' do
          subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
            expect(namespace_module).not_to eq @existent_namespace_module

            expect {
              namespace_module::MetasploitModule
            }.to raise_error(NameError)

            true
          end
        end

        context 'with an Exception from the block' do
          let(:error_class) do
            NameError
          end

          let(:error_message) do
            "SayMyName"
          end

          it 'should restore the previous namespace module' do
            expect(Msf::Modules.const_get(relative_name)).to eq @existent_namespace_module

            begin
              subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
                current_constant = Msf::Modules.const_get(relative_name)

                expect(current_constant).to eq namespace_module
                expect(current_constant).not_to eq @existent_namespace_module

                raise error_class, error_message
              end
            rescue error_class => error
            end

            expect(Msf::Modules.const_get(relative_name)).to eq @existent_namespace_module
          end

          it 'should re-raise the error' do
            expect {
              subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
                raise error_class, error_message
              end
            }.to raise_error(error_class, error_message)
          end
        end

        context 'with the block returning false' do
          it 'should restore the previous namespace module' do
            expect(Msf::Modules.const_get(relative_name)).to eq @existent_namespace_module

            subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
              current_constant = Msf::Modules.const_get(relative_name)

              expect(current_constant).to eq namespace_module
              expect(current_constant).not_to eq @existent_namespace_module

              false
            end

            expect(Msf::Modules.const_get(relative_name)).to eq @existent_namespace_module
          end

          it 'should return false' do
            expect(
              subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
                false
              }
            ).to eq false
          end
        end

        context 'with the block returning true' do
          it 'should not restore the previous namespace module' do
            expect(Msf::Modules.const_get(relative_name)).to eq @existent_namespace_module

            subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
              true
            end

            current_constant = Msf::Modules.const_get(relative_name)

            expect(current_constant).not_to be_nil
            expect(current_constant).not_to eq @existent_namespace_module
          end

          it 'should return true' do
            expect(
              subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
                true
              }
            ).to eq true
          end
        end
      end

      context 'without pre-existing namespace module' do
        before(:example) do
          relative_name = self.relative_name

          if Msf::Modules.const_defined? relative_name
            Msf::Modules.send(:remove_const, relative_name)
          end
        end

        it 'should create a new namespace module' do
          expect {
            Msf::Modules.const_get(relative_name)
          }.to raise_error(NameError)

          subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
            expect(Msf::Modules.const_get(relative_name)).to eq namespace_module
          end
        end

        context 'with an Exception from the block' do
          let(:error_class) do
            Exception
          end

          let(:error_message) do
            'Error Message'
          end

          it 'should remove the created namespace module' do
            expect(Msf::Modules.const_defined?(relative_name)).to be_falsey

            begin
              subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
                expect(Msf::Module.const_defined?(relative_name)).to be_truthy

                raise error_class, error_message
              end
            rescue error_class
            end

            expect(Msf::Modules.const_defined?(relative_name)).to be_falsey
          end

          it 'should re-raise the error' do
            expect {
              subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
                raise error_class, error_message
              end
            }.to raise_error(error_class, error_message)
          end
        end

        context 'with the block returning false' do
          it 'should remove the created namespace module' do
            expect(Msf::Modules.const_defined?(relative_name)).to be_falsey

            subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
              expect(Msf::Modules.const_defined?(relative_name)).to be_truthy

              false
            end

            expect(Msf::Modules.const_defined?(relative_name)).to be_falsey
          end

          it 'should return false' do
            expect(
              subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
                false
              }
            ).to eq false
          end
        end

        context 'with the block returning true' do
          it 'should not restore the non-existent previous namespace module' do
            expect(Msf::Modules.const_defined?(relative_name)).to be_falsey

            created_namespace_module = nil

            subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
              expect(Msf::Modules.const_defined?(relative_name)).to be_truthy

              created_namespace_module = namespace_module

              true
            end

            expect(Msf::Modules.const_defined?(relative_name)).to be_truthy
            expect(Msf::Modules.const_get(relative_name)).to eq created_namespace_module
          end

          it 'should return true' do
            expect(
              subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
                true
              }
            ).to eq true
          end
        end
      end
    end

    context '#read_module_content' do
      it 'should be abstract' do
        type = Msf::MODULE_AUX

        expect {
          subject.send(:read_module_content, parent_pathname.to_s, type, module_reference_name)
        }.to raise_error(NotImplementedError)
      end
    end

    context '#restore_namespace_module' do
      let(:parent_module) do
        Msf::Modules
      end

      let(:relative_name) do
        'Auxiliary__Rspec__Mock'
      end

      it 'should do nothing if parent_module is nil' do
        parent_module = nil

        # can check that NoMethodError is not raised because *const* methods are
        # not defined on `nil`.
        expect {
          subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)
        }.to_not raise_error
      end

      context 'with namespace_module nil' do
        include_context 'Metasploit::Framework::Spec::Constants cleaner'

        #
        # lets
        #

        let(:namespace_module) do
          nil
        end

        #
        # Callbacks
        #

        before(:example) do
          parent_module.const_set(relative_name, Module.new)
        end

        it 'should remove relative_name' do
          expect(parent_module).to receive(:remove_const).with(relative_name).and_call_original

          subject.send(:restore_namespace_module, parent_module, relative_name, namespace_module)
        end

        it 'should not set the relative_name constant to anything' do
          expect(parent_module).not_to receive(:const_set)

          subject.send(:restore_namespace_module, parent_module, relative_name, namespace_module)
        end
      end

      context 'with parent_module and namespace_module' do
        before(:example) do
          module Msf
            module Modules
              module Auxiliary__Rspec__Mock
                class Metasploit

                end
              end
            end
          end

          @original_namespace_module = Msf::Modules::Auxiliary__Rspec__Mock

          Msf::Modules.send(:remove_const, relative_name)
        end

        context 'with relative_name being a defined constant' do
          before(:example) do
            module Msf
              module Modules
                module Auxiliary__Rspec__Mock
                  class Metasploit2

                  end
                end
              end
            end

            @current_namespace_module = Msf::Modules::Auxiliary__Rspec__Mock
          end

          context 'with the current constant being the namespace_module' do
            include_context 'Metasploit::Framework::Spec::Constants cleaner'

            it 'should not change the constant' do
              expect(parent_module.const_defined?(relative_name)).to be_truthy

              current_module = parent_module.const_get(relative_name)
              expect(current_module).to eq @current_namespace_module

              subject.send(:restore_namespace_module, parent_module, relative_name, @current_namespace_module)

              expect(parent_module.const_defined?(relative_name)).to be_truthy
              restored_module = parent_module.const_get(relative_name)
              expect(restored_module).to eq current_module
              expect(restored_module).to eq @current_namespace_module
            end

            it 'should not remove the constant and then set it' do
              # Allow 'Metasploit::Framework::Spec::Constants cleaner' removal
              expect(parent_module).to receive(:remove_const).with(relative_name.to_sym).and_call_original

              expect(parent_module).not_to receive(:remove_const).with(relative_name)
              expect(parent_module).not_to receive(:const_set).with(relative_name, @current_namespace_module)

              subject.send(:restore_namespace_module, parent_module, relative_name, @current_namespace_module)
            end
          end

          context 'without the current constant being the namespace_module' do
            include_context 'Metasploit::Framework::Spec::Constants cleaner'

            it 'should remove relative_name from parent_module' do
              expect(parent_module.const_defined?(relative_name)).to be_truthy

              expect(parent_module).to receive(:remove_const).with(relative_name).and_call_original
              expect(parent_module).to receive(:remove_const).with(relative_name.to_sym).and_call_original

              subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)
            end

            it 'should restore the module to the constant' do
              expect(parent_module.const_get(relative_name)).not_to eq @original_namespace_module

              subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)

              expect(parent_module.const_get(relative_name)).to eq @original_namespace_module
            end
          end
        end

        context 'without relative_name being a defined constant' do
          include_context 'Metasploit::Framework::Spec::Constants cleaner'

          it 'should set relative_name on parent_module to namespace_module' do
            expect(parent_module.const_defined?(relative_name)).to be_falsey

            subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)

            expect(parent_module.const_defined?(relative_name)).to be_truthy
            expect(parent_module.const_get(relative_name)).to eq @original_namespace_module
          end
        end
      end
    end

    context '#typed_path' do
      it 'should delegate to the class method' do
        type = Msf::MODULE_EXPLOIT

        expect(described_class).to receive(:typed_path).with(type, module_reference_name)
        subject.send(:typed_path, type, module_reference_name)
      end
    end
  end
end
