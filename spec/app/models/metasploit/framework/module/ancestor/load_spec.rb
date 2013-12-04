require 'spec_helper'

require 'file/find'

describe Metasploit::Framework::Module::Ancestor::Load do
  include_context 'database cleaner'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'

  subject(:module_ancestor_load) do
    described_class.new(
        module_ancestor: module_ancestor
    )
  end

  let(:module_ancestor) do
    FactoryGirl.create(:mdm_module_ancestor)
  end

  it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Load::NamespaceModule'

  context 'validations' do
    context 'metasploit_module' do
      context 'presence' do
        let(:error) do
          I18n.translate('errors.messages.blank')
        end

        before(:each) do
          module_ancestor_load.stub(:metasploit_module => metasploit_module)

          # for #module_ancestor_valid
          module_ancestor_load.valid?(validation_context)
        end

        context 'with :loading validation context' do
          let(:validation_context) do
            :loading
          end

          context 'with nil' do
            let(:metasploit_module) do
              nil
            end

            it 'should not add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should_not include(error)
            end
          end

          context 'without nil' do
            let(:metasploit_module) do
              Module.new
            end

            it 'should not add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should_not include(error)
            end
          end
        end

        context 'without validation context' do
          let(:validation_context) do
            nil
          end

          context 'with nil' do
            let(:metasploit_module) do
              nil
            end

             it 'should add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should include(error)
            end
          end

          context 'without nil' do
            let(:metasploit_module) do
              Module.new.tap { |metasploit_module|
                # needs to be stubbed for #metasploit_module_valid
                metasploit_module.stub(invalid?: false)
              }
            end

            it 'should not add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should_not include(error)
            end
          end
        end
      end

      context 'recursive' do
        let(:error) do
          I18n.translate('errors.messages.invalid')
        end

        let(:metasploit_module) do
          double('Metasploit Module')
        end

        let(:valid?) do
          false
        end

        before(:each) do
          metasploit_module.stub(invalid?: !valid?)
          module_ancestor_load.stub(metasploit_module: metasploit_module)

          # for module_ancestor recursive validation
          module_ancestor_load.valid?(validation_context)
        end

        context 'with :loading validation context' do
          let(:validation_context) do
            :loading
          end

          it 'should pass validation_context to module_ancestor.invalid?' do
            module_ancestor.should_receive(:invalid?).with(validation_context)

            # for module_ancestor recursive validation
            module_ancestor_load.valid?(validation_context)
          end

          context 'with valid' do
            let(:valid?) do
              true
            end

            it 'should not add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should_not include(error)
            end
          end

          context 'without valid' do
            let(:valid?) do
              false
            end

            it 'should not add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should_not include(error)
            end
          end
        end

        context 'without validation context' do
          let(:validation_context) do
            nil
          end

          context 'with valid' do
            let(:valid?) do
              true
            end

            it 'should not add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should_not include(error)
            end
          end

          context 'without valid' do
            let(:valid?) do
              false
            end

            it 'should add error on :metasploit_module' do
              module_ancestor_load.errors[:metasploit_module].should include(error)
            end
          end
        end
      end
    end

    context 'module_ancestor' do
      it { should validate_presence_of :module_ancestor }

      context 'recursive' do
        let(:error) do
          I18n.translate('errors.messages.invalid')
        end

        context 'with nil' do
          before(:each) do
            module_ancestor_load.module_ancestor = nil
            module_ancestor_load.valid?
          end

          it 'should not add error on :module_ancestor' do
            module_ancestor_load.errors[:module_ancestor].should_not include(error)
          end
        end

        context 'without nil' do
          before(:each) do
            module_ancestor.stub(invalid?: !valid?, valid?: valid?)

            module_ancestor_load.valid?
          end

          context 'with valid' do
            let(:valid?) do
              true
            end

            it 'should not add error on :module_ancestor' do
              module_ancestor_load.errors[:module_ancestor].should_not include(error)
            end
          end

          context 'without valid' do
            let(:valid?) do
              false
            end

            it 'should add error on :module_ancestor' do
              module_ancestor_load.errors[:module_ancestor].should include(error)
            end
          end
        end
      end
    end
  end

  context '#loading_context?' do
    subject(:loading_context?) do
      module_ancestor_load.send(:loading_context?)
    end

    context 'with :loading validation_context' do
      it 'should be true' do
        module_ancestor_load.should_receive(:run_validations!) do
          loading_context?.should be_true
        end

        module_ancestor_load.valid?(:loading)
      end
    end

    context 'without validation_context' do
      it 'should be false' do
        module_ancestor_load.should_receive(:run_validations!) do
          loading_context?.should be_false
        end

        module_ancestor_load.valid?
      end
    end
  end

  context '#metasploit_module' do
    subject(:metasploit_module) do
      module_ancestor_load.metasploit_module
    end

    before(:each) do
      module_ancestor_load.stub(namespace_module: namespace_module)
    end

    context 'with #namespace_module' do
      let(:namespace_module_metasploit_module) do
        double('Metasploit Module')
      end

      let(:namespace_module) do
        double(
            'Namespace Module',
            metasploit_module: namespace_module_metasploit_module
        )
      end

      it 'should return namespace_module.metasploit_module' do
        metasploit_module.should == namespace_module_metasploit_module
      end
    end

    context 'without #namespace_module' do
      let(:namespace_module) do
        nil
      end

      it { should be_nil }
    end
  end

  context '#metasploit_module_valid' do
    subject(:metasploit_module_valid) do
      module_ancestor_load.send(:metasploit_module_valid)
    end

    let(:error) do
      I18n.translate('errors.messages.invalid')
    end

    before(:each) do
      module_ancestor_load.stub(metasploit_module: metasploit_module)
    end

    context 'with #metasploit_module' do
      let(:metasploit_module) do
        double('Metasploit Module', invalid?: !valid?)
      end

      context 'with valid' do
        let(:valid?) do
          true
        end

        it 'should not add error on :metasploit_module' do
          metasploit_module_valid

          module_ancestor_load.errors[:metasploit_module].should_not include(error)
        end
      end

      context 'without valid' do
        let(:valid?) do
          false
        end

        it 'should not add error on :metasploit_module' do
          metasploit_module_valid

          module_ancestor_load.errors[:metasploit_module].should include(error)
        end
      end
    end

    context 'without #metasploit_module' do
      let(:metasploit_module) do
        nil
      end

      it 'should not add error on :metasploit_module' do
        metasploit_module_valid

        module_ancestor_load.errors[:metasploit_module].should_not include(error)
      end
    end
  end

  context '#module_ancestor_valid' do
    subject(:module_ancestor_valid) do
      module_ancestor_load.send(:module_ancestor_valid)
    end

    let(:error) do
      I18n.translate('errors.messages.invalid')
    end

    context 'with #module_ancestor' do
      before(:each) do
        module_ancestor.stub(invalid?: !valid?, valid?: valid?)
      end

      context 'with valid' do
        let(:valid?) do
          true
        end

        it 'should not add error on :module_ancestor' do
          module_ancestor_valid

          module_ancestor_load.errors[:module_ancestor].should_not include(error)
        end
      end

      context 'without valid' do
        let(:valid?) do
          false
        end

        it 'should add error on :module_ancestor' do
          module_ancestor_valid

          module_ancestor_load.errors[:module_ancestor].should include(error)
        end
      end
    end

    context 'without #module_ancestor' do
      let(:module_ancestor) do
        nil
      end

      it 'should not add error on :module_ancestor' do
        module_ancestor_valid

        module_ancestor_load.errors[:module_ancestor].should_not include(error)
      end
    end
  end

  context '#namespace_module' do
    subject(:namespace_module) do
      module_ancestor_load.namespace_module
    end

    context 'with valid for loading' do
      it 'should be valid for loading' do
        module_ancestor_load.should be_valid(:loading)
      end

      it 'should call namespace_module_transaction' do
        module_ancestor_load.should_receive(:namespace_module_transaction).with(module_ancestor)

        namespace_module
      end

      context 'module_ancestor_eval' do
        let(:transaction_namespace_module) do
          double('Transaction Namespace Module').tap { |namespace_module|
            validation_proxy = Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy.new(target: namespace_module)
            namespace_module.stub(errors: validation_proxy.errors)
            namespace_module.stub(:module_ancestor_eval).with(module_ancestor).and_return(success)
            namespace_module.stub(:valid?)
          }
        end

        context 'with success' do
          let(:success) do
            true
          end

          it 'should return true from namespace_module_transaction block' do
            module_ancestor_load.should_receive(:namespace_module_transaction) do |&block|
              block.call(module_ancestor, transaction_namespace_module).should be_true
            end

            namespace_module
          end

          it 'should be transaction namespace module' do
            module_ancestor_load.should_receive(:namespace_module_transaction) do |&block|
              block.call(module_ancestor, transaction_namespace_module)
            end

            namespace_module.should == transaction_namespace_module
          end
        end

        context 'without success' do
          let(:success) do
            false
          end

          it 'should validation the namespace_module' do
            module_ancestor_load.should_receive(:namespace_module_transaction) do |&block|
              transaction_namespace_module.should_receive(:valid?)
              block.call(module_ancestor, transaction_namespace_module)
            end

            namespace_module
          end

          it 'should set @namespace_module_errors' do
            module_ancestor_load.should_receive(:namespace_module_transaction) do |&block|
              block.call(module_ancestor, transaction_namespace_module)
            end

            expect {
              namespace_module
            }.to change {
              module_ancestor_load.instance_variable_get :@namespace_module_errors
            }
          end

          it 'should return false from namespace_module_transaction block' do
            module_ancestor_load.should_receive(:namespace_module_transaction) do |&block|
              block.call(module_ancestor, transaction_namespace_module).should be_false
            end

            namespace_module
          end

          it 'should be nil' do
            module_ancestor_load.should_receive(:namespace_module_transaction) do |&block|
              block.call(module_ancestor, transaction_namespace_module)
            end

            namespace_module.should be_nil
          end
        end
      end
    end

    context 'without valid for loading' do
      let(:module_ancestor) do
        FactoryGirl.build(:mdm_module_ancestor, module_type: nil, reference_name: nil, real_path: nil)
      end

      it 'should not be valid for loading' do
        module_ancestor_load.should_not be_valid(:loading)
      end

      it { should be_nil }
    end
  end

  context '#namespace_module_errors' do
    subject(:namespace_module_errors) do
      module_ancestor_load.namespace_module_errors
    end

    context 'with defined' do
      let(:expected_namespace_module_errors) do
        double('ActiveModel::Errors')
      end

      before(:each) do
        module_ancestor_load.instance_variable_set :@namespace_module_errors, expected_namespace_module_errors
      end

      it 'should not call #namespace_module' do
        module_ancestor_load.should_not_receive(:namespace_module)

        namespace_module_errors
      end

      it 'should return already defined namespace_module_errors' do
        namespace_module_errors.should == expected_namespace_module_errors
      end
    end

    context 'without defined' do
      it 'should call #namespace_module' do
        module_ancestor_load.should_receive(:namespace_module)

        namespace_module_errors
      end

      context '#namespace_module' do
        before(:each) do
          module_ancestor_load.stub(namespace_module: namespace_module)
        end

        context 'with nil' do
          let(:namespace_module) do
            nil
          end

          it { should be_nil }
        end

        context 'without nil' do
          let(:errors) do
            double('Errors')
          end

          let(:namespace_module) do
            double('Namespace Module', errors: errors)
          end

          it 'should return namespace_modules.errors' do
            namespace_module_errors.should == errors
          end

        end
      end
    end
  end

  context 'files' do
    module_path_real_path = Metasploit::Framework.root.join('modules').to_path

    let(:module_path) do
      FactoryGirl.create(
          :mdm_module_path,
          gem: 'metasploit-framework',
          name: 'modules',
          real_path: module_path_real_path
      )
    end

    rule = File::Find.new(
        ftype: 'file',
        pattern: "*#{Metasploit::Model::Module::Ancestor::EXTENSION}",
        path: module_path_real_path
    )

    rule.find { |real_path|
      real_pathname = Pathname.new(real_path)
      relative_pathname = real_pathname.relative_path_from(Metasploit::Framework.root)

      # have context be path relative to project root so context name is consistent no matter where the specs run
      context "#{relative_pathname}" do
        let(:module_ancestor) do
          module_path.module_ancestors.build(real_path: real_path)
        end

        it { should load_metasploit_module }
      end
    }
  end
end