shared_examples_for 'Metasploit::Framework::Module::Ancestor::Load::NamespaceModule' do
  let(:pathname) do
    Metasploit::Framework.root.join(
        'lib',
        'metasploit',
        'framework',
        'module',
        'ancestor',
        'load',
        'namespace_module.rb'
    )
  end

  context 'CONSTANTS' do
    context 'NAMESPACE_MODULE_LINE' do
      it 'should be line number for first line of NAMESPACE_MODULE_CONTENT' do
        file_lines = []

        pathname.open do |f|
          file_lines = f.to_a
        end

        # -1 because file lines are 1-based, but array is 0-based
        file_line = file_lines[described_class::NAMESPACE_MODULE_LINE - 1]

        constant_lines = described_class::NAMESPACE_MODULE_CONTENT.lines.to_a
        constant_line = constant_lines.first

        file_line.should == constant_line
      end
    end


    context 'NAMESPACE_MODULE_CONTENT' do
      context 'derived module' do
        include_context 'Msf::Modules Cleaner'

        let(:namespace_module_names) do
          ['Msf', 'Modules', 'RealPathSha1HexDigest0123456789']
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

        context 'module_eval_with_lexical_scope' do
          let(:malformed_module_content) do
            <<-EOS
            class Metasploit3
              # purposeful typo to check that module path is used in backtrace
              inclde Exploit::Remote::Tcp
            end
            EOS
          end

          let(:module_content) do
            <<-EOS
            class Metasploit3 < Msf::Auxiliary
              # fully-qualified name is Msf::GoodRanking, so this will failing if lexical scope is not captured
              Rank = GoodRanking
            end
            EOS
          end

          it 'should capture the lexical scope' do
            expect {
              namespace_module.module_eval_with_lexical_scope(module_content, module_ancestor.real_path)
            }.to_not raise_error(NameError)
          end

          context 'with malformed module content' do
            it 'should use module path in module_eval' do
              error = nil

              begin
                namespace_module.module_eval_with_lexical_scope(malformed_module_content, module_ancestor.real_path)
              rescue NoMethodError => error
                # don't put the should in the rescue because if there is no error, then the example will still be
                # successful.
              end

              error.should_not be_nil
              error.backtrace[0].should include(module_ancestor.real_path)
            end
          end
        end
      end
    end

    context 'NAMESPACE_MODULE_NAMES' do
      it 'should be under Msf so that Msf constants resolve from lexical scope' do
        described_class::NAMESPACE_MODULE_NAMES.should include('Msf')
      end

      it "should not be directly under Msf so that modules don't collide with core namespaces" do
        direct_index = described_class::NAMESPACE_MODULE_NAMES.index('Msf')
        last_index = described_class::NAMESPACE_MODULE_NAMES.length - 1

        last_index.should > direct_index
      end
    end
  end

  context '#create_namespace_module' do
    include_context 'Msf::Modules Cleaner'

    let(:namespace_module_names) do
      [
          'Msf',
          'Modules',
          relative_name
      ]
    end

    let(:relative_name) do
      'Mod0'
    end

    it 'should wrap NAMESPACE_MODULE_CONTENT with module declarations matching namespace_module_names' do
      Object.should_receive(
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

      namespace_module = mock('Namespace Module')
      namespace_module.stub(:loader=)
      subject.stub(:current_module => namespace_module)

      subject.send(:create_namespace_module, namespace_module_names)
    end

    it "should set the module_eval path to the loader's __FILE__" do
      Object.should_receive(
          :module_eval
      ).with(
          anything,
          pathname.to_path,
          anything
      )

      namespace_module = mock('Namespace Module')
      namespace_module.stub(:loader=)
      subject.stub(:current_module => namespace_module)

      subject.send(:create_namespace_module, namespace_module_names)
    end

    it 'should set the module_eval line to compensate for the wrapping module declarations' do
      Object.should_receive(
          :module_eval
      ).with(
          anything,
          anything,
          described_class::NAMESPACE_MODULE_LINE - namespace_module_names.length
      )

      namespace_module = mock('Namespace Module')
      namespace_module.stub(:loader=)
      subject.stub(:current_module => namespace_module)

      subject.send(:create_namespace_module, namespace_module_names)
    end
  end

  context '#current_module' do
    include_context 'Msf::Modules Cleaner'

    let(:module_names) do
      [
          'Msf',
          'Modules',
          relative_name
      ]
    end

    let(:relative_name) do
      'Mod0'
    end

    before(:each) do
      # copy to local variable so it is accessible in instance_eval
      relative_name = self.relative_name

      if Msf::Modules.const_defined? relative_name
        Msf::Modules.instance_eval do
          remove_const relative_name
        end
      end
    end

    it 'should return nil if the module is not defined' do
      Msf::Modules.const_defined?(relative_name).should be_false
      subject.send(:current_module, module_names).should be_nil
    end

    it 'should return the module if it is defined' do
      Object.module_eval <<-EOS
        module #{module_names[0]}
          module #{module_names[1]}
            module #{module_names[2]}
            end
          end
        end
      EOS

      subject.send(:current_module, module_names).should == Msf::Modules::Mod0
    end
  end

  context '#namespace_module_names' do
    subject(:namespace_module_names) do
      module_ancestor_load.namespace_module_names(module_ancestor)
    end

    it "should prefix the array with ['Msf', 'Modules']" do
      namespace_module_names.should start_with(['Msf', 'Modules'])
    end

    it 'should prefix the relative name with RealPathSha1HexDigest' do
      namespace_module_names.last.should start_with('RealPathSha1HexDigest')
    end

    it 'should include Metasploit::Model::Module::Ancestor#real_path_sha1_hex_digest' do
      namespace_module_names.last.should include(module_ancestor.real_path_sha1_hex_digest)
    end
  end

  context '#namespace_module_transaction' do
    include_context 'Msf::Modules Cleaner'

    # need to take a custom block, so can't use subject
    def namespace_module_transaction(&block)
      module_ancestor_load.send(:namespace_module_transaction, module_ancestor, &block)
    end

    let(:fully_qualified_name) do
      "Msf::Modules::#{relative_name}"
    end

    let(:relative_name) do
      "RealPathSha1HexDigest#{module_ancestor.real_path_sha1_hex_digest}"
    end

    context 'with pre-existing namespace module' do
      let(:existent_namespace_module) do
        fully_qualified_name.constantize
      end

      before(:each) do
        Object.module_eval <<-EOS
          module Msf
            module Modules
              module #{relative_name}
                class Metasploit4

                end
              end
            end
          end
        EOS

        # ensure namespace Module is captured after declaration
        existent_namespace_module
      end

      it 'should remove the pre-existing namespace module' do
        # once in namespace_module_transaction and once at end of this example
        Msf::Modules.should_receive(:remove_const).with(relative_name).twice.and_call_original

        namespace_module_transaction do |module_ancestor, namespace_module|
          # commit transaction
          true
        end

        # clean up so Msf::Modules Cleaner doesn't trigger should_receive
        Msf::Modules.send(:remove_const, relative_name)
      end

      it 'should create a new namespace module for the block' do
        namespace_module_transaction do |module_ancestor, namespace_module|
          namespace_module.should_not == existent_namespace_module

          expect {
            # the metasploit_module should not be defined in the new namespace_module because
            # namespace_module.module_ancestor_eval has not been called yet.
            namespace_module::Metasploit4
          }.to raise_error(NameError)

          # commit transaction
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
          Msf::Modules.const_get(relative_name).should == existent_namespace_module

          begin
            namespace_module_transaction do |_module_ancestor, namespace_module|
              current_constant = Msf::Modules.const_get(relative_name)

              current_constant.should == namespace_module
              current_constant.should_not == existent_namespace_module

              raise error_class, error_message
            end
          rescue error_class => error
            error
          end

          Msf::Modules.const_get(relative_name).should == existent_namespace_module
        end

        it 'should re-raise the error' do
          expect {
            namespace_module_transaction do |_module_ancestor, _namespace_module|
              raise error_class, error_message
            end
          }.to raise_error(error_class, error_message)
        end
      end

      context 'with the block returning false' do
        it 'should restore the previous namespace module' do
          Msf::Modules.const_get(relative_name).should == existent_namespace_module

          namespace_module_transaction do |_module_ancestor, namespace_module|
            current_constant = Msf::Modules.const_get(relative_name)

            current_constant.should == namespace_module
            current_constant.should_not == existent_namespace_module

            false
          end

          Msf::Modules.const_get(relative_name).should == existent_namespace_module
        end

        it 'should return false' do
          namespace_module_transaction { |_module_ancestor, namespace_module|
            false
          }.should be_false
        end
      end

      context 'with the block returning true' do
        it 'should not restore the previous namespace module' do
          Msf::Modules.const_get(relative_name).should == existent_namespace_module

          namespace_module_transaction do |_module_ancestor, _namespace_module|
            true
          end

          current_constant = Msf::Modules.const_get(relative_name)

          current_constant.should_not be_nil
          current_constant.should_not == existent_namespace_module
        end

        it 'should return true' do
          namespace_module_transaction { |_module_ancesotr, _namespace_module|
            true
          }.should be_true
        end
      end
    end

    context 'without pre-existing namespace module' do
      before(:each) do
        relative_name = self.relative_name

        if Msf::Modules.const_defined? relative_name
          Msf::Modules.send(:remove_const, relative_name)
        end
      end

      it 'should create a new namespace module' do
        expect {
          Msf::Modules.const_get(relative_name)
        }.to raise_error(NameError)

        namespace_module_transaction do |_module_ancestor, namespace_module|
          Msf::Modules.const_get(relative_name).should == namespace_module
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
          Msf::Modules.const_defined?(relative_name).should be_false

          begin
            namespace_module_transaction do |_module_ancestor, _namespace_module|
              Msf::Module.const_defined?(relative_name).should be_true

              raise error_class, error_message
            end
          rescue error_class
          end

          Msf::Modules.const_defined?(relative_name).should be_false
        end

        it 'should re-raise the error' do
          expect {
            namespace_module_transaction do |_module_ancestor, _namespace_module|
              raise error_class, error_message
            end
          }.to raise_error(error_class, error_message)
        end
      end

      context 'with the block returning false' do
        it 'should remove the created namespace module' do
          Msf::Modules.const_defined?(relative_name).should be_false

          namespace_module_transaction do |_module_ancestor, _namespace_module|
            Msf::Modules.const_defined?(relative_name).should be_true

            false
          end

          Msf::Modules.const_defined?(relative_name).should be_false
        end

        it 'should return false' do
          namespace_module_transaction { |_module_ancestor, _namespace_module|
            false
          }.should be_false
        end
      end

      context 'with the block returning true' do
        it 'should not restore the non-existent previous namespace module' do
          Msf::Modules.const_defined?(relative_name).should be_false

          created_namespace_module = nil

          namespace_module_transaction do |_module_ancestor, namespace_module|
            Msf::Modules.const_defined?(relative_name).should be_true

            created_namespace_module = namespace_module

            true
          end

          Msf::Modules.const_defined?(relative_name).should be_true
          Msf::Modules.const_get(relative_name).should == created_namespace_module
        end

        it 'should return true' do
          namespace_module_transaction { |_module_ancestor, _namespace_module|
            true
          }.should be_true
        end
      end
    end
  end

  context '#restore_namespace_module' do
    include_context 'Msf::Modules Cleaner'

    def restore_namespace_module(parent_module, relative_name, namespace_module)
      module_ancestor_load.send(:restore_namespace_module, parent_module, relative_name, namespace_module)
    end

    let(:parent_module) do
      Msf::Modules
    end

    let(:relative_name) do
      'Mod0'
    end

    it 'should do nothing if parent_module is nil' do
      parent_module = nil

      # can check that NoMethodError is not raised because *const* methods are
      # not defined on `nil`.
      expect {
        restore_namespace_module(parent_module, relative_name, @original_namespace_module)
      }.to_not raise_error(NoMethodError)
    end

    context 'with namespace_module nil' do
      let(:namespace_module) do
        nil
      end

      it 'should not set the relative_name constant to anything' do
        parent_module.should_not_receive(:const_set)

        restore_namespace_module(parent_module, relative_name, namespace_module)
      end
    end

    context 'with parent_module and namespace_module' do
      let(:fully_qualified_name) do
        "Msf::Modules::#{relative_name}"
      end

      before(:each) do
        Object.module_eval <<-EOS
          module Msf
            module Modules
              module #{relative_name}
                class Metasploit3

                end
              end
            end
          end
        EOS

        @original_namespace_module = fully_qualified_name.constantize

        Msf::Modules.send(:remove_const, relative_name)
      end

      context 'with relative_name being a defined constant' do
        before(:each) do
          Object.module_eval <<-EOS
            module Msf
              module Modules
                module #{relative_name}
                  class Metasploit2

                  end
                end
              end
            end
          EOS

          @current_namespace_module = fully_qualified_name.constantize
        end

        context 'with the current constant being the namespace_module' do
          it 'should not change the constant' do
            parent_module.const_defined?(relative_name).should be_true

            current_module = parent_module.const_get(relative_name)
            current_module.should == @current_namespace_module

            restore_namespace_module(parent_module, relative_name, @current_namespace_module)

            parent_module.const_defined?(relative_name).should be_true
            restored_module = parent_module.const_get(relative_name)
            restored_module.should == current_module
            restored_module.should == @current_namespace_module
          end

          it 'should not remove the constant and then set it' do
            parent_module.should_not_receive(:remove_const).with(relative_name)
            parent_module.should_not_receive(:const_set).with(relative_name, @current_namespace_module)

            restore_namespace_module(parent_module, relative_name, @current_namespace_module)
          end
        end

        context 'without the current constant being the namespace_module' do
          it 'should remove relative_name from parent_module' do
            parent_module.const_defined?(relative_name).should be_true
            # once in restore_namespace_module and once at the of this example
            parent_module.should_receive(:remove_const).with(relative_name).twice.and_call_original

            restore_namespace_module(parent_module, relative_name, @original_namespace_module)

            # remove restored original_namespace_module so Msf::Module Cleaner doesn't trigger
            parent_module.send(:remove_const, relative_name)
          end

          it 'should restore the module to the constant' do
            parent_module.const_get(relative_name).should_not == @original_namespace_module

            restore_namespace_module(parent_module, relative_name, @original_namespace_module)

            parent_module.const_get(relative_name).should == @original_namespace_module
          end
        end
      end

      context 'without relative_name being a defined constant' do
        it 'should set relative_name on parent_module to namespace_module' do
          parent_module.const_defined?(relative_name).should be_false

          restore_namespace_module(parent_module, relative_name, @original_namespace_module)

          parent_module.const_defined?(relative_name).should be_true
          parent_module.const_get(relative_name).should == @original_namespace_module
        end
      end
    end
  end
end