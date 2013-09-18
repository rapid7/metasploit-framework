require 'spec_helper'

describe Metasploit::Framework::Module::Path::Load do
  subject(:module_path_load) do
    described_class.new
  end

  context 'factories' do
    context 'metasploit_framework_module_path_load' do
      include_context 'database cleaner'

      subject(:metasploit_framework_module_path_load) do
        with_established_connection do
          FactoryGirl.build(:metasploit_framework_module_path_load)
        end
      end

      it { should be_valid }
    end
  end

  context 'validations' do
    it { should validate_presence_of :cache }
    it { should ensure_inclusion_of(:changed).in_array([false, true]) }
    it { should validate_presence_of :module_path }

    context 'module_ancestor_loads' do
      context 'recursive' do
        context 'with :loading validation context' do
          it 'should not call #module_ancestor_loads_valid' do
            module_path_load.should_not_receive(:module_ancestor_loads_valid)

            module_path_load.valid?(:loading)
          end
        end

        context 'without validation context' do
          let(:error) do
            I18n.translate('errors.messages.invalid')
          end

          let(:module_ancestor_loads) do
            []
          end

          before(:each) do
            module_path_load.stub(module_ancestor_loads: module_ancestor_loads)
          end

          it 'should call #module_ancestor_loads_valid' do
            module_path_load.should_receive(:module_ancestor_loads_valid)

            module_path_load.valid?
          end

          context 'with #module_ancestor_loads' do
            let(:module_ancestor_loads) do
              2.times.collect { |n|
                double("Metasploit::Framework::Module::Ancestor::Load #{n}", valid?: true)
              }
            end

            context 'with all valid' do
              it 'should not add error to :module_ancestor_loads' do
                module_path_load.valid?

                module_path_load.errors[:module_ancestor_loads].should_not include(error)
              end
            end

            context 'without all valid' do
              before(:each) do
                module_ancestor_loads.first.stub(valid?: false)
              end

              it 'should add error to :module_ancestor_loads' do
                module_path_load.valid?

                module_path_load.errors[:module_ancestor_loads].should include(error)
              end
            end
          end

          context 'without #module_ancestor_loads' do
            it 'should not add error to :module_ancestor_loads' do
              module_path_load.valid?

              module_path_load.errors[:module_ancestor_loads].should_not include(error)
            end
          end
        end
      end
    end
  end

  context '#changed' do
    subject(:changed) do
      module_path_load.changed
    end

    it 'should default to false' do
      changed.should be_false
    end

    it 'should be settable and gettable' do
      changed = double('Changed')
      module_path_load.changed = changed
      module_path_load.changed.should == changed
    end
  end

  context '#loading_context?' do
    subject(:loading_context?) do
      module_path_load.send(:loading_context?)
    end

    context 'with :loading validation_context' do
      it 'should be true' do
        module_path_load.should_receive(:run_validations!) do
          loading_context?.should be_true
        end

        module_path_load.valid?(:loading)
      end
    end

    context 'without validation_context' do
      it 'should be false' do
        module_path_load.should_receive(:run_validations!) do
          loading_context?.should be_false
        end

        module_path_load.valid?
      end
    end
  end

  context '#module_ancestor_loads' do
    include_context 'database cleaner'

    subject(:module_ancestor_loads) do
      with_established_connection do
        module_path_load.module_ancestor_loads
      end
    end

    it 'should memoize' do
      memoized = double('#module_ancestor_loads')
      module_path_load.instance_variable_set :@module_ancestor_loads, memoized

      module_ancestor_loads.should == memoized
    end

    context 'with valid for loading' do
      let(:module_path) do
        module_path_load.module_path
      end

      let(:module_path_load) do
        with_established_connection do
          FactoryGirl.build(:metasploit_framework_module_path_load)
        end
      end

      it 'should be valid?(:loading)' do
        module_path_load.valid?(:loading)
      end

      it 'should pass #changed to Mdm::Module::Path#each_changed_module_ancestor as :change option' do
        module_path.should_receive(:each_changed_module_ancestor).with(
            hash_including(
                changed: module_path_load.changed
            )
        )

        module_ancestor_loads
      end

      context 'with no changed module ancestors' do
        it { should be_empty }
      end

      context 'with changed module ancestors' do
        let!(:module_ancestors) do
          with_established_connection do
            # Build instead of create so only the on-disk file is created and not saved to the database so the
            # Mdm::Module::Ancestors count as changed (since they are new)
            FactoryGirl.build_list(:mdm_module_ancestor, 2, parent_path: module_path)
          end
        end

        it 'should be an Array<Metasploit::Framework::Module::Ancestor::Load>' do
          module_ancestor_loads.should be_an Array

          module_ancestor_loads.all? { |module_ancestor_load|
            module_ancestor_load.is_a? Metasploit::Framework::Module::Ancestor::Load
          }.should be_true
        end

        it 'should make a Metasploit::Framework::Module::Ancestor::Load for each changed module ancestor' do
          module_ancestor_loads.length.should == module_ancestors.length

          # have to compare by real_path as module_ancestors are not saved to the database, so can't compare
          # ActiveRecords since they compare by #id.
          actual_real_paths = module_ancestor_loads.map(&:module_ancestor).map(&:real_path)
          expected_real_paths = module_ancestors.map(&:derived_real_path)
          expect(actual_real_paths).to match_array(expected_real_paths)
        end
      end
    end

    context 'without valid for loading' do
      it { should be_nil }
    end
  end

  context '#module_type_enabled?' do
    subject(:module_type_enabled?) do
      module_path_load.module_type_enabled? module_type
    end

    let(:cache) do
      double('Metasploit::Framework::Module::Cache')
    end

    let(:module_type) do
      FactoryGirl.generate :metasploit_model_module_type
    end

    before(:each) do
      module_path_load.stub(cache: cache)
    end

    it 'should delegate to #cache' do
      cache.should_receive(:module_type_enabled?).with(module_type)

      module_type_enabled?
    end
  end
end