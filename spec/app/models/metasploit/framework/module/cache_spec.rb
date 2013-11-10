require 'spec_helper'

require 'file/find'

describe Metasploit::Framework::Module::Cache do
  subject(:module_cache) do
    described_class.new
  end

  context 'CONSTANTS' do
    context 'MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE' do
      include_context 'database seeds'

      subject(:module_class_load_class) do
        described_class::MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE[module_class.module_type][module_class.payload_type]
      end

      context 'module_type' do
        let(:module_class) do
          with_established_connection {
            FactoryGirl.create(
                :mdm_module_class,
                module_type: module_type
            )
          }
        end

        context 'with auxiliary' do
          let(:module_type) do
            'auxiliary'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with encoder' do
          let(:module_type) do
            'encoder'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with exploit' do
          let(:module_type) do
            'encoder'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with nop' do
          let(:module_type) do
            'encoder'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with payload' do
          let(:module_type) do
            'payload'
          end

          context 'payload_type' do
            let(:module_class) do
              with_established_connection {
                FactoryGirl.create(
                    :mdm_module_class,
                    module_type: module_type,
                    payload_type: payload_type
                )
              }
            end

            context 'with single' do
              let(:payload_type) do
                'single'
              end

              it { should == Metasploit::Framework::Module::Class::Load::Payload::Single }
            end

            context 'with staged' do
              let(:payload_type) do
                'staged'
              end

              it { should == Metasploit::Framework::Module::Class::Load::Payload::Staged }
            end
          end
        end

        context 'with post' do
          let(:module_type) do
            'post'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end
      end
    end
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

  context '#framework' do
    subject(:framework) do
      module_cache.framework
    end

    let(:expected_framework) do
      double('Msf::Framework')
    end

    let(:module_manager) do
      double('Msf::ModuleManager', framework: expected_framework)
    end

    before(:each) do
      module_cache.stub(module_manager: module_manager)
    end

    it 'should delegate to #module_manager' do
      framework.should == module_manager.framework
    end
  end

  context '#metasploit_class' do
    include_context 'database seeds'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    subject(:metasploit_class) do
      with_established_connection {
        module_cache.metasploit_class(module_class)
      }
    end

    context 'module_type' do
      let(:module_class) do
        with_established_connection {
          # have to build instead of create since invalid module_type and payload_types are being tested
          FactoryGirl.build(
              :mdm_module_class,
              module_type: module_type,
              payload_type: payload_type
          )
        }
      end

      before(:each) do
        # validate to trigger derivations
        module_class.valid?
      end

      context 'with valid' do
        Metasploit::Model::Module::Type::NON_PAYLOAD.each do |module_type|
          it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load non-payload',
                                module_type: module_type
        end

        context 'with payload' do
          let(:module_type) do
            'payload'
          end

          context 'payload_type' do
            context 'with single' do
              let(:payload_type) do
                'single'
              end

              it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load',
                                    module_class_load_class: Metasploit::Framework::Module::Class::Load::Payload::Single
            end

            context 'with staged' do
              let(:payload_type) do
                'staged'
              end

              it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load',
                                    module_class_load_class: Metasploit::Framework::Module::Class::Load::Payload::Staged
            end

            context 'with nil' do
              let(:payload_type) do
                FactoryGirl.generate :metasploit_model_module_class_payload_type
              end

              before(:each) do
                # set after build or ancestors won't be setup correctly and factory will raise ArgumentError
                module_class.payload_type = nil
              end

              it { should be_nil }
            end
          end
        end
      end

      context 'without valid' do
        let(:module_type) do
          'unknown_module_type'
        end
      end
    end
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
      include_context 'database seeds'

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
            Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                hash_including(
                    module_path: only
                )
            ).and_call_original

            prefetch
          end

          it 'should set Metasploit::Framework::Module::Path::Load#cache' do
            Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                hash_including(
                    cache: module_cache
                )
            ).and_call_original

            prefetch
          end

          it 'should iterate through Metasploit::Framework::Module::Ancestor::Loads' do
            Metasploit::Framework::Module::Path::Load.any_instance.should_receive(:each_module_ancestor_load)

            prefetch
          end

          it 'should write each Metasploit::Framework::Module::Ancestor::Load to the cache' do
            module_ancestor_loads = 2.times.collect { |n|
              double("Metasploit::Framework::Module::Ancestor::Load #{n}")
            }
            expectation = Metasploit::Framework::Module::Path::Load.any_instance.should_receive(:each_module_ancestor_load)

            module_ancestor_loads.inject(expectation) { |expectation, module_ancestor_load|
              expectation.and_yield(module_ancestor_load)
            }

            module_ancestor_loads.each do |module_ancestor_load|
              module_cache.should_receive(:write_module_ancestor_load).with(module_ancestor_load)
            end

            prefetch
          end
        end

        context 'with Array<Metasploit::Model::Module::Path>' do
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
            only.each do |module_path|
              Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                  hash_including(
                      module_path: module_path
                  )
              ).and_call_original
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

        it 'should use all Metasploit::Model::Module::Paths in #path_set' do
          path_set.should_receive(:all).and_return([])

          prefetch
        end

        it 'should have Metasploit::Framework::Module::Path::Load for each Metasploit::Model::Module::Path' do
          module_paths.each do |module_path|
            Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                hash_including(
                    module_path: module_path
                )
            ).and_call_original
          end

          prefetch
        end
      end
    end

    context 'with real module files' do
      include_context 'database cleaner', after: :all
      include_context 'database seeds', scope: :all
      include_context 'Metasploit::Framework::Spec::Constants cleaner', after: :all
      include_context 'profile'

      module_path_real_pathname = Metasploit::Framework.root.join('modules')

      before(:all) do
        module_cache = FactoryGirl.create(:metasploit_framework_module_cache)

        module_manager = module_cache.module_manager
        module_manager.should_not be_nil

        framework = module_manager.framework
        framework.should_not be_nil

        with_established_connection do
          @module_path = FactoryGirl.create(
              :mdm_module_path,
              gem: 'metasploit-framework',
              name: 'modules',
              real_path: module_path_real_pathname.to_path
          )

          module_cache.path_set.add(@module_path.real_path, gem: 'metasploit-framework', name: 'modules')

          log_pathname = Metasploit::Framework.root.join('log', "#{Metasploit::Framework.env}.log")
          log = log_pathname.open('w')
          ActiveRecord::Base.logger = Logger.new(log)

          GC.start
          profile('double-prefetch.active_record_base_logger') do
            # with cache empty   all misses
            module_cache.prefetch(only: @module_path)
            # with cache full   all hits
            module_cache.prefetch(only: @module_path)
            GC.start
          end

          ActiveRecord::Base.logger = nil
        end
      end

      context '#module_type' do
        context 'with payload' do
          context '#payload_type' do
            it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with payload',
                                  module_classes: :have_exactly,
                                  payload_type: 'single'

            it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with payload',
                                  module_classes: :have_at_least,
                                  payload_type: 'stage'

            it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with payload',
                                  module_classes: :have_at_least,
                                  payload_type: 'stager'
          end
        end

        Metasploit::Model::Module::Type::NON_PAYLOAD.each do |module_type|
          it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with non-payload',
                                module_type: module_type

        end
      end
    end
  end
end