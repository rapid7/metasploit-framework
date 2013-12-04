require 'spec_helper'

describe Metasploit::Framework::Module::Path::Load do
  subject(:module_path_load) do
    described_class.new
  end

  context 'factories' do
    context 'metasploit_framework_module_path_load' do
      include_context 'database cleaner'

      subject(:metasploit_framework_module_path_load) do
        FactoryGirl.build(:metasploit_framework_module_path_load)
      end

      it { should be_valid }
    end
  end

  context 'validations' do
    it { should validate_presence_of :cache }
    it { should ensure_inclusion_of(:changed).in_array([false, true]) }
    it { should validate_presence_of :module_path }
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

  context '#each_module_ancestor_load' do
    include_context 'database cleaner'

    subject(:each_module_ancestor_load) do
      module_path_load.each_module_ancestor_load
    end

    context 'with module path load valid' do
      let(:module_path) do
        module_path_load.module_path
      end

      let(:module_path_load) do
        FactoryGirl.build(:metasploit_framework_module_path_load)
      end

      let(:progress_bar) do
        module_path_load.progress_bar
      end

      it 'should have valid module path load' do
        module_path_load.should be_valid
      end

      it 'should set #progress_bar #title to #module_path #real_path' do
        # stub so database connection isn't needed
        module_path.stub(:each_changed_module_ancestor)

        progress_bar.should_receive(:title=).with(module_path_load.module_path.real_path)

        each_module_ancestor_load.to_a
      end

      it 'should pass #changed to Mdm::Module::Path#each_changed_module_ancestor as :change option' do
        module_path.should_receive(:each_changed_module_ancestor).with(
            hash_including(
                changed: module_path_load.changed
            )
        )

        each_module_ancestor_load.to_a
      end

      it 'should pass #progress_bar to Mdm::Module::Path#each_changed_module_ancestor as :progress_bar option' do
        module_path.should_receive(:each_changed_module_ancestor).with(
            hash_including(
                progress_bar: progress_bar
            )
        )

        each_module_ancestor_load.to_a
      end

      context 'with no changed module ancestors' do
        specify {
          expect { |block|
            module_path_load.each_module_ancestor_load(&block)
          }.not_to yield_control
        }
      end

      context 'with changed module ancestors' do
        let!(:module_ancestors) do
          # Build instead of create so only the on-disk file is created and not saved to the database so the
          # Mdm::Module::Ancestors count as changed (since they are new)
          FactoryGirl.build_list(:mdm_module_ancestor, 2, parent_path: module_path)
        end

        it 'should yield Metasploit::Framework::Module::Ancestor::Load' do
          module_path_load.each_module_ancestor_load do |module_ancestor_load|
            module_ancestor_load.should be_a Metasploit::Framework::Module::Ancestor::Load
          end
        end

        it 'should make a Metasploit::Framework::Module::Ancestor::Load for each changed module ancestor' do
          actual_real_paths = []

          module_path_load.each_module_ancestor_load do |module_ancestor_load|
            actual_real_paths << module_ancestor_load.module_ancestor.real_path
          end

          # have to compare by real_path as module_ancestors are not saved to the database, so can't compare
          # ActiveRecords since they compare by #id.
          expected_real_paths = module_ancestors.map(&:derived_real_path)
          expect(actual_real_paths).to match_array(expected_real_paths)
        end
      end
    end

    context 'without valid module path load' do
      it 'should have invalid module path load' do
        module_path_load.should be_invalid
      end

      specify {
        expect { |block|
          module_path_load.each_module_ancestor_load(&block)
        }.not_to yield_control
      }
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

  context '#progress_bar' do
    subject(:progress_bar) do
      module_path_load.progress_bar
    end

    context 'with default' do
      it { should be_a Metasploit::Framework::NullProgressBar }
    end

    context 'without default' do
      #
      # lets
      #

      let(:module_path_load) do
        described_class.new(progress_bar: progress_bar)
      end

      let(:progress_bar) do
        double('ProgressBar')
      end

      it 'should be the progress bar passed to #initialize as :progress_bar' do
        module_path_load.progress_bar.should == progress_bar
      end
    end
  end
end