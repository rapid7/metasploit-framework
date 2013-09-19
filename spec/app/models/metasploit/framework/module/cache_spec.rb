require 'spec_helper'

require 'file/find'

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
    context 'with factories' do
      include_context 'database cleaner'
      include_context 'database seeds'
      include_context 'Msf::Modules Cleaner'

      #
      # lets
      #

      let(:module_cache) do
        FactoryGirl.create(:metasploit_framework_module_cache)
      end

      let(:module_manager) do
        module_cache.module_manager
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

          it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch deriving module classes' do
            let(:module_ancestors_by_module_type) do
              module_ancestors_by_module_type = Hash.new { |hash, module_type|
                hash[module_type] = []
              }

              module_ancestors.each do |module_ancestor|
                if module_ancestor.parent_path == only
                  module_ancestors_by_module_type[module_ancestor.module_type] << module_ancestor
                end
              end

              module_ancestors_by_module_type
            end
          end

          context 'Metasploit::Model::Module::Ancestor#module_type' do
            context 'with payload' do
              it 'should create an Mdm::Module::Ancestor for each Metasploit::Model::Module::Ancestor#real_path under Metasploit::Model::Module::Path#real_path'

              it 'should create at least one Mdm::Module::Class for each Metasploit::Model::Module::Ancestor#real_path under Metasploit::Model::Module::Path#real_path'
            end

            context 'without payload' do
              let!(:module_ancestors) do
                module_paths.flat_map { |module_path|
                  with_established_connection do
                    # build instead of create so Mdm::Module::Ancestors will be seen as new and changed since unchanged ones
                    # won't be prefetched.
                    2.times.collect {
                      module_type = FactoryGirl.generate :metasploit_model_module_type

                      module_ancestor = FactoryGirl.build(
                          :mdm_module_ancestor,
                          module_type: module_type,
                          parent_path: module_path
                      )
                      # Defines rank_number in Metasploit::Model::Module::Ancestor#content
                      FactoryGirl.build(
                          :mdm_module_class,
                          ancestors: [
                              module_ancestor
                          ]
                      )

                      module_ancestor
                    }
                  end
                }
              end

              let(:only_module_ancestors) do
                module_ancestors.select { |module_ancestor|
                  module_ancestor.parent_path == only
                }
              end

              it 'should create an Mdm::Module::Ancestor for each Metasploit::Model::Module::Ancestor#real_path under Metasploit::Model::Module::Path#real_path' do
                prefetch

                only_module_ancestors.each do |module_ancestor|
                  real_path = module_ancestor.derived_real_path

                  with_established_connection do
                    Mdm::Module::Ancestor.where(real_path: real_path).should exist
                  end
                end
              end

              it 'should create an Mdm::Module::Class for each Metasploit::Model::Module::Ancestor#real_path under Metasploit::Model::Module::Path#real_path' do
                prefetch

                only_module_ancestors.each do |expected_module_ancestor|
                  real_path = expected_module_ancestor.derived_real_path

                  with_established_connection do
                    actual_module_ancestor = Mdm::Module::Ancestor.where(real_path: real_path).first
                    actual_module_ancestor.should have(1).descendants
                  end
                end
              end
            end
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

          it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch deriving module classes' do
            let(:module_ancestors_by_module_type) do
              module_ancestors_by_module_type = Hash.new { |hash, module_type|
                hash[module_type] = []
              }

              module_ancestors.each do |module_ancestor|
                if only.include? module_ancestor.parent_path
                  module_ancestors_by_module_type[module_ancestor.module_type] << module_ancestor
                end
              end

              module_ancestors_by_module_type
            end
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

        it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch deriving module classes' do
          let(:module_ancestors_by_module_type) do
            module_ancestors.group_by(&:module_type)
          end
        end
      end
    end

    context 'with real module files' do
      include_context 'database cleaner', after: :all
      include_context 'database seeds', scope: :all
      include_context 'Msf::Modules Cleaner', after: :all
      include_context 'profile'

      module_path_real_pathname = Metasploit::Framework.root.join('modules')

      before(:all) do
        module_manager = Msf::ModuleManager.new

        module_cache = described_class.new(
            module_manager: module_manager
        )

        with_established_connection do
          @module_path = FactoryGirl.create(
              :mdm_module_path,
              gem: 'metasploit-framework',
              name: 'modules',
              real_path: module_path_real_pathname.to_path
          )

          module_cache.path_set.add(@module_path.real_path, gem: 'metasploit-framework', name: 'modules')

          GC.start
          profile('double-prefetch.without-uniqueness-validations') do
            # with cache empty - all misses
            module_cache.prefetch(only: @module_path)
            # with cache full - all hits
            module_cache.prefetch(only: @module_path)
            GC.start
          end
        end
      end

      File::Find.with_options(ftype: 'file', pattern: "*#{Metasploit::Model::Module::Ancestor::EXTENSION}") do |module_file_find|
        context '#module_type' do
          context 'with payload' do
            context '#payload_type' do
              context 'with single' do
                it 'should work'
              end

              context 'with stage' do
                it 'should work'
              end

              context 'with stager' do
                it 'should work'
              end
            end
          end

          non_payload_module_types = Metasploit::Model::Module::Type::ALL - [Metasploit::Model::Module::Type::PAYLOAD]

          non_payload_module_types.each do |module_type|
            context "with #{module_type}" do
              module_type_directory = Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[module_type]
              module_type_path = module_path_real_pathname.join(module_type_directory).to_path
              rule = module_file_find.new(path: module_type_path)

              rule.find { |real_path|
                real_pathname = Pathname.new(real_path)
                relative_pathname = real_pathname.relative_path_from(Metasploit::Framework.root)

                # have context be path relative to project root so context name is consistent no matter where the specs run
                context "#{relative_pathname}" do
                  let(:module_ancestor) do
                    with_established_connection {
                      @module_path.module_ancestors.where(real_path: real_path).first
                    }
                  end

                  it 'should have Mdm::Module::Ancestor' do
                    module_ancestor.should_not be_nil
                  end

                  it 'should have one Mdm::Module::Class' do
                    module_ancestor.should_not be_nil

                    with_established_connection do
                      module_ancestor.should have(1).descendants
                    end
                  end
                end
              }
            end
          end
        end
      end
    end
  end
end