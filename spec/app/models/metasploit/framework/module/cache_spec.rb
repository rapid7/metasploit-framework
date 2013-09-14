require 'spec_helper'

describe Metasploit::Framework::Module::Cache do
  subject(:module_cache) do
    described_class.new
  end

  context 'factories' do
    context 'metasploit_framework_module_cache' do
      subject(:metasploit_framework_module_cache) do
        FactoryGirl.build(:metasploit_framework_module_cache)
      end

      it { should be_valid }
    end
  end

  context 'validations' do
    it { should validate_presence_of :module_manager }
  end

  context '#module_type_enabled?' do
    subject(:module_type_enabled?) do
      module_cache.module_type_enabled?(module_type)
    end

    let(:module_manager) do
      double('Msf::ModuleManager')
    end

    let(:module_type) do
      FactoryGirl.generate :metasploit_model_module_type
    end

    before(:each) do
      module_cache.module_manager = module_manager
    end

    it 'should delegate to #module_manager' do
      module_manager.should_receive(:module_type_enabled?).with(module_type)

      module_type_enabled?
    end
  end

  context '#path_set' do
    subject(:path_set) do
      module_cache.path_set
    end

    it 'should be memoized' do
      memoized = double('Metasploit::Framework::Module::PathSet::Database')
      module_cache.instance_variable_set :@path_set, memoized

      path_set.should == memoized
    end

    it { should be_a Metasploit::Framework::Module::PathSet::Base }

    it 'should be validated' do
      Metasploit::Framework::Module::PathSet::Base.any_instance.should_receive(:valid!)

      path_set
    end

    context 'cache' do
      subject(:cache) do
        path_set.cache
      end

      it 'should be parent module cache' do
        cache.should == module_cache
      end
    end
  end

  context '#prefetch' do
    include_context 'DatabaseCleaner'
    include_context 'Msf::Modules Cleaner'

    #
    # lets
    #

    let(:module_cache) do
      described_class.new(
          module_manager: module_manager
      )
    end

    let(:module_manager) do
      double('Msf::ModuleManager').tap { |module_manager|
        module_set = double('Msf::ModuleSet', recalculate: nil)
        module_manager.stub(:module_set).with(an_instance_of(String)).and_return(module_set)
      }
    end

    let(:path_set) do
      module_cache.path_set
    end

    #
    # let!s
    #

    let!(:module_ancestors) do
      module_paths.flat_map { |module_path|
        with_established_connection do
          # build instead of create so Mdm::Module::Ancestors will be seen as new and changed since unchanged ones
          # won't be prefetched.
          FactoryGirl.build_list(:mdm_module_ancestor, 2, parent_path: module_path)
        end
      }
    end

    let!(:module_paths) do
      with_established_connection do
        FactoryGirl.create_list(:mdm_module_path, 3)
      end
    end

    context 'with :only' do
      subject(:prefetch) do
        with_established_connection do
          module_cache.prefetch only: only
        end
      end

      context 'with Metasploit::Model::Module::Path' do
        let(:module_path_load) do
          prefetch.first
        end

        let(:only) do
          module_paths.sample
        end

        it 'should have Metasploit::Model::Module::Path for :only option' do
          only.should be_a Metasploit::Model::Module::Path
        end

        it 'should ensure that #path_set contains Metasploit::Model::Module::Path' do
          path_set.should_receive(:superset!).with([only])

          prefetch
        end

        it 'should have Metasploit::Framework::Module::Path::Load for Metasploit::Model::Module::Path' do
          module_path_load.module_path.should == only
        end

        it 'should set Metasploit::Framework::Module::Path::Load#cache' do
          module_path_load.cache.should == module_cache
        end

        it 'should recalculate module_set for Metasploit::Model::Module::Path#module_ancestors Metasploit::Model::Module::Ancestor#module_type' do
          module_path_module_ancestors = module_ancestors.select { |module_ancestor|
            module_ancestor.parent_path == only
          }

          module_type_set = module_path_module_ancestors.each_with_object(Set.new) { |module_ancestor, set|
            set.add module_ancestor.module_type
          }

          module_type_set.each do |module_type|
            module_set = double("#{module_type} Msf::ModuleSet")
            module_set.should_receive(:recalculate)

            module_manager.stub(:module_set).with(module_type).and_return(module_set)
          end

          prefetch
        end
      end

      context 'with Array<Metasploit::Model::Module::Path>' do
        let(:module_path_loads) do
          prefetch
        end

        let(:only) do
          module_paths.sample(2)
        end

        it 'should have Array for :only option' do
          only.should be_an Array
        end

        it 'should ensure that #path_set contains all Metasploit::Model::Module::Paths' do
          path_set.should_receive(:superset!).with(only)

          prefetch
        end

        it 'should have Metasploit::Framework::Module::Path::Load for each Metasploit::Model::Module::Path' do
          module_paths = module_path_loads.map(&:module_path)

          expect(module_paths).to match_array(only)
        end

        it 'should recalculate module_set for Metasploit::Model::Module::Path#module_ancestors Metasploit::Model::Module::Ancestor#module_type' do
          module_path_module_ancestors = module_ancestors.select { |module_ancestor|
            only.include? module_ancestor.parent_path
          }

          module_type_set = module_path_module_ancestors.each_with_object(Set.new) { |module_ancestor, set|
            set.add module_ancestor.module_type
          }

          module_type_set.each do |module_type|
            module_set = double("#{module_type} Msf::ModuleSet")
            module_set.should_receive(:recalculate)

            module_manager.stub(:module_set).with(module_type).and_return(module_set)
          end

          prefetch
        end
      end
    end

    context 'without :only' do
      subject(:prefetch) do
        with_established_connection do
          module_cache.prefetch
        end
      end

      let(:module_path_loads) do
        prefetch
      end

      it 'should use all Metasploit::Model::Module::Paths in #path_set' do
        path_set.should_receive(:all).and_return([])

        prefetch
      end

      it 'should have Metasploit::Framework::Module::Path::Load for each Metasploit::Model::Module::Path' do
        actual_module_paths = module_path_loads.map(&:module_path)

        expect(actual_module_paths).to match_array(module_paths)
      end

      it 'should recalculate module_set for Metasploit::Model::Module::Path#module_ancestors Metasploit::Model::Module::Ancestor#module_type' do
        module_type_set = module_ancestors.each_with_object(Set.new) { |module_ancestor, set|
          set.add module_ancestor.module_type
        }

        module_type_set.each do |module_type|
          module_set = double("#{module_type} Msf::ModuleSet")
          module_set.should_receive(:recalculate)

          module_manager.stub(:module_set).with(module_type).and_return(module_set)
        end

        prefetch
      end
    end
  end
end