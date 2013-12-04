require 'spec_helper'

require 'weakref'

require 'msf/core/module/platform_list'

describe Metasploit::Framework::Module::Ancestor::MetasploitModule do
  include_context 'database cleaner'

  subject(:metasploit_module) do
    rank = self.rank

    Module.new.tap { |m|
      m.define_singleton_method(:rank_name) do
        rank.name
      end

      if ['single', 'stager'].include? module_class_module_ancestor.payload_type
        m.extend Metasploit::Framework::Module::Ancestor::Handler
      end
    }
  end

  let(:module_class_module_ancestor) do
    module_class.ancestors.first
  end

  let(:module_class) do
    FactoryGirl.build(
        :mdm_module_class,
        # nil rank as #cache is expected to set rank
        rank: nil
    )
  end

  let(:parent_module) do
    module_ancestor = self.module_class_module_ancestor
    # ensure derivations have run
    module_ancestor.valid?

    Module.new.tap { |m|
      m.define_singleton_method(:module_type) do
        module_ancestor.module_type
      end

      m.define_singleton_method(:payload_type) do
        module_ancestor.payload_type
      end

      m.define_singleton_method(:payload?) do
        module_ancestor.payload?
      end

      m.define_singleton_method(:real_path_sha1_hex_digest) do
        module_ancestor.real_path_sha1_hex_digest
      end
    }
  end

  let(:rank) do
    FactoryGirl.generate :mdm_module_rank
  end

  before(:each) do
    stub_const('Parent', parent_module)
    stub_const('Parent::Child', metasploit_module)
    # have to extend after being assigned a name or delegation to parent won't work in described_class.extended.
    metasploit_module.extend described_class
  end

  it_should_behave_like 'Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache'

  it_should_behave_like 'Metasploit::Framework::ProxiedValidation' do
    let(:target) do
      metasploit_module
    end
  end

  context 'CONSTANTS' do
    context 'PAIRED_PAYLOAD_TYPE_BY_PAYLOAD_TYPE' do
      subject(:paired_payload_type_by_payload_type) do
        described_class::PAIRED_PAYLOAD_TYPE_BY_PAYLOAD_TYPE
      end

      its(['stage']) { should == 'stager' }
      its(['stager']) { should == 'stage' }
    end
  end

  context 'resurrecting attributes' do
    context '#module_ancestor' do
      subject(:module_ancestor) do
        metasploit_module.module_ancestor
      end

      let(:expected_module_ancestor) do
        FactoryGirl.create(:mdm_module_ancestor)
      end

      before(:each) do
        # have to stub because real_path_sha1_hex_digest is normally delegated to the namespace parent
        metasploit_module.stub(real_path_sha1_hex_digest: expected_module_ancestor.real_path_sha1_hex_digest)
      end

      it 'should be Mdm::Module::Ancestor with matching #real_path_sha1_hex_digest' do
        module_ancestor.should == expected_module_ancestor
      end
    end
  end

  context 'validations' do
    context 'usable' do
      context 'default' do
        it { should be_valid }
      end

      context 'with is_usable false' do
        let(:error) do
          I18n.translate('metasploit.model.errors.models.metasploit/framework/module/ancestor/metasploit_module.attributes.base.unusable')
        end

        before(:each) do
          metasploit_module.module_eval do
            def self.is_usable
              false
            end
          end
        end

        it { should_not be_valid }

        it 'should add error on :base' do
          metasploit_module.valid?

          metasploit_module.errors[:base].should include(error)
        end
      end
    end
  end

  context '#each_compatible_metasploit_module' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    # no subject() since need to pass block
    def each_compatible_metasploit_module(&block)
      metasploit_module.each_compatible_metasploit_module(&block)
    end

    let(:module_class) do
      FactoryGirl.build(
          :mdm_module_class,
          module_type: 'payload',
          payload_type: 'staged'
      )
    end

    it 'should call each_paired_metasploit_module' do
      metasploit_module.should_receive(:each_paired_metasploit_module)

      each_compatible_metasploit_module { }
    end

    context 'with paired metasploit modules' do
      let(:architectures) do
        2.times.collect {
          FactoryGirl.generate :mdm_architecture
        }
      end

      let(:architecture_abbreviations) do
        architectures.map(&:abbreviation)
      end

      let(:pair_count) do
        2
      end

      let(:paired_metasploit_classes) do
        pair_count.times.collect { |n|
          double("paired_metasploit_class #{n}")
        }
      end

      let(:paired_metasploit_instances) do
        pair_count.times.collect { |n|
          double("paired_metasploit_instance #{n}")
        }
      end

      let(:paired_metasploit_modules) do
        pair_count.times.collect { |n|
          double("paired_metasploit_module #{n}")
        }
      end

      let(:paired_platforms) do
        # there are n pairs
        pair_count.times.collect {
          # each pair has 2 platforms
          2.times.collect {
            FactoryGirl.generate :mdm_platform
          }
        }
      end

      let(:paired_platform_fully_qualified_names) do
        paired_platforms.collect { |platforms|
          platforms.map(&:fully_qualified_name)
        }
      end

      let(:payload_metasploit_class) do
        metasploit_module.payload_metasploit_class
      end

      let(:platforms) do
        2.times.collect {
          FactoryGirl.generate :mdm_platform
        }
      end

      let(:platform_fully_qualified_names) do
        platforms.map(&:fully_qualified_name)
      end

      before(:each) do
        paired_metasploit_instances.zip(paired_platform_fully_qualified_names) do |(instance, platform_fully_qualified_names)|
          instance.should_receive(:platform).and_return(platform_fully_qualified_names)
        end

        paired_metasploit_classes.zip(paired_metasploit_instances) do |class_and_instance|
          klass, instance = class_and_instance
          klass.should_receive(:new).and_return(instance)
        end

        paired_metasploit_modules.zip(paired_metasploit_classes) do |module_and_class|
          mod, klass = module_and_class
          mod.should_receive(:payload_metasploit_class).and_return(klass)
        end

        expectation = metasploit_module.should_receive(:each_paired_metasploit_module)

        paired_metasploit_modules.inject(expectation) do |expectation, paired_metasploit_module|
          expectation.and_yield(paired_metasploit_module)
        end

        payload_metasploit_class.any_instance.should_receive(
            :platform
        ).exactly(
            paired_metasploit_modules.length
        ).times.and_return(
            platform_fully_qualified_names
        )
      end

      it 'should call #payload_metasploit_class once to get instance metadata' do
        payload_metasploit_class = metasploit_module.payload_metasploit_class
        metasploit_module.should_receive(:payload_metasploit_class).once.and_return(payload_metasploit_class)

        each_compatible_metasploit_module { }
      end

      it 'should instantiate #payload_metasploit_class once' do
        payload_metasploit_instance = self.payload_metasploit_class.new

        payload_metasploit_class = double('#payload_metasploit_class')
        payload_metasploit_class.should_receive(:new).once.and_return(payload_metasploit_instance)

        metasploit_module.should_receive(:payload_metasploit_class).once.and_return(payload_metasploit_class)

        each_compatible_metasploit_module { }
      end

      context 'with common platforms' do
        let(:paired_platform_fully_qualified_names) do
          pair_count.times.collect {
            # pass sample size so it comes back as an Array
            platform_fully_qualified_names.sample(1)
          }
        end

        before(:each) do
          payload_metasploit_class.any_instance.should_receive(
              :arch
          ).exactly(
              paired_metasploit_modules.length
          ).times.and_return(
              architecture_abbreviations
          )
        end

        it 'should check for common architectures' do
          paired_metasploit_instances.each do |instance|
            instance.should_receive(:arch).and_return([])
          end

          each_compatible_metasploit_module { }
        end

        context 'with common architectures' do
          let(:paired_architecture_abbreviations) do
            pair_count.times.collect {
              # pass sample size so it comes back as an Array
              architecture_abbreviations.sample(1)
            }
          end

          before(:each) do
            paired_metasploit_instances.zip(paired_architecture_abbreviations) do |instance_and_architecture_abbreviations|
              instance, architecture_abbreviations = instance_and_architecture_abbreviations
              instance.should_receive(:arch).and_return(architecture_abbreviations)
            end
          end

          context '#payload_type' do
            let(:module_class_module_ancestor) do
              module_class.ancestors.find { |ancestor|
                ancestor.payload_type == payload_type
              }
            end

            context 'with stage' do
              let(:compatible) do
                false
              end

              let(:payload_type) do
                'stage'
              end

              before(:each) do
                paired_metasploit_instances.each do |paired_metasploit_instance|
                  payload_metasploit_class.any_instance.should_receive(:compatible?).with(paired_metasploit_instance).and_return(compatible)
                end
              end

              it 'should call #compatible?' do
                each_compatible_metasploit_module { }
              end

              context 'with compatible' do
                let(:compatible) do
                  true
                end

                it 'should yield each compatible paired metasploit module' do
                  expect { |block|
                    each_compatible_metasploit_module(&block)
                  }.to yield_successive_args(*paired_metasploit_modules)
                end
              end

              context 'without compatible' do
                specify {
                  expect { |block|
                    each_compatible_metasploit_module(&block)
                  }.not_to yield_control
                }
              end
            end

            context 'with stager' do
              let(:compatible) do
                false
              end

              let(:payload_type) do
                'stager'
              end

              before(:each) do
                paired_metasploit_instances.each do |paired_metasploit_instance|
                  paired_metasploit_instance.should_receive(:compatible?).with(
                      an_instance_of(payload_metasploit_class)
                  ).and_return(compatible)
                end
              end

              it 'should call #compatible?' do
                each_compatible_metasploit_module { }
              end

              context 'with compatible' do
                let(:compatible) do
                  true
                end

                it 'should yield each compatible paired metasploit module' do
                  expect { |block|
                    each_compatible_metasploit_module(&block)
                  }.to yield_successive_args(*paired_metasploit_modules)
                end
              end

              context 'without compatible' do
                specify {
                  expect { |block|
                    each_compatible_metasploit_module(&block)
                  }.not_to yield_control
                }
              end
            end
          end
        end

        context 'without common architectures' do
          before(:each) do
            paired_metasploit_instances.each do |paired_metasploit_instance|
              paired_metasploit_instance.should_receive(:arch).and_return([])
            end
          end

          specify {
            expect { |block|
              each_compatible_metasploit_module(&block)
            }.not_to yield_control
          }
        end
      end

      context 'without common platforms' do
        specify {
          expect { |block|
            each_compatible_metasploit_module(&block)
          }.not_to yield_control
        }
      end
    end
  end

  context '#each_metasploit_classes' do
    include_context 'database cleaner'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    # no subject() since we need to take a block and don't want to have a fixed block in context
    def each_metasploit_class(&block)
      metasploit_module.each_metasploit_class(&block)
    end

    let(:metasploit_module) do
      module_ancestor_load.metasploit_module
    end

    let(:module_ancestor_load) do
      Metasploit::Framework::Module::Ancestor::Load.new(
          module_ancestor: module_ancestor
      )
    end

    context '#module_type' do
      let(:module_ancestor) do
        FactoryGirl.create(
            :mdm_module_ancestor,
            module_type: module_type,
            payload_type: payload_type
        )
      end

      context 'with payload' do
        let(:module_type) do
          Metasploit::Model::Module::Type::PAYLOAD
        end

        context 'payload_type' do
          #
          # let
          #

          let(:architectures) do
            2.times.collect {
              FactoryGirl.generate :mdm_architecture
            }
          end

          let(:architecture_abbreviations) do
            architectures.map(&:abbreviation)
          end

          let(:platforms) do
            2.times.collect {
              FactoryGirl.generate :mdm_platform
            }
          end

          let(:platform_fully_qualified_names) do
            platforms.map(&:fully_qualified_name)
          end

          context 'with single' do
            let(:payload_type) do
              'single'
            end

            it 'should contain only one Class' do
              count = 0

              each_metasploit_class do |metasploit_class|
                metasploit_class.should be_a Class
                count += 1
              end

              count.should == 1
            end

            context 'metasploit_class' do
              subject(:metasploit_class) do
                each_metasploit_class.first
              end

              it 'should be a subclass of Msf::Payload' do
                expect(metasploit_class).to be < Msf::Payload
              end

              it 'should include this metasploit module' do
                metasploit_class.should include(metasploit_module)
              end

              it 'should include handler_module' do
                metasploit_class.should include(metasploit_module.handler_module)
              end
            end
          end

          context 'with stage' do
            let(:payload_type) do
              'stage'
            end

            context 'with no compatible stagers' do
              it 'should contain no Classes' do
                expect { |block|
                  each_metasploit_class(&block)
                }.not_to yield_control
              end
            end

            context 'with compatible stagers' do
              let!(:stager_module_ancestors) do
                FactoryGirl.create_list(
                    :mdm_module_ancestor,
                    2,
                    module_type: 'payload',
                    payload_type: 'stager'
                )
              end

              let!(:stager_metasploit_modules) do
                stager_module_ancestors.collect { |module_ancestor|
                  namespace = Module.new.tap do |namespace|
                    namespace.module_eval Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_CONTENT,
                                          Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_FILE,
                                          Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_LINE
                  end

                  namespace.module_type = module_ancestor.module_type
                  namespace.payload_type = module_ancestor.payload_type
                  namespace.real_path_sha1_hex_digest = module_ancestor.real_path_sha1_hex_digest

                  Msf::Modules.const_set("RealPathSha1HexDigest#{module_ancestor.real_path_sha1_hex_digest}", namespace)

                  namespace.module_ancestor_eval(module_ancestor)

                  namespace.metasploit_module
                }
              end

              before(:each) do
                architecture_abbreviations = self.architecture_abbreviations
                platform_fully_qualified_names = self.platform_fully_qualified_names

                [metasploit_module, *stager_metasploit_modules].each do |compatible_module|
                  compatible_module.send(:define_method, :arch) do
                    architecture_abbreviations
                  end

                  compatible_module.send(:define_method, :platform) do
                    platform_fully_qualified_names
                  end
                end
              end

              it 'should yield a Class for each compatible pair' do
                count = 0

                each_metasploit_class do |metasploit_class|
                  metasploit_class.should be_a Class
                  count += 1
                end

                count.should == stager_module_ancestors.length
              end

              context 'metasploit_classes' do
                subject(:metasploit_classes) do
                  each_metasploit_class
                end

                it 'should be subclasses of Msf::Payload' do
                  each_metasploit_class do |metasploit_class|
                    expect(metasploit_class).to be < Msf::Payload
                  end
                end

                it 'should include this metasploit module' do
                  each_metasploit_class do |metasploit_class|
                    metasploit_class.should include(metasploit_module)
                  end
                end

                it 'should include handler_module from stagers' do
                  each_metasploit_class do |metasploit_class|
                    stager_metasploit_modules.one? { |stager_metasploit_module|
                      metasploit_class.include? stager_metasploit_module.handler_module
                    }.should be_true
                  end
                end

                it 'should include metasploit module from stager' do
                  each_metasploit_class do |metasploit_class|
                    intersection = metasploit_class.ancestors & stager_metasploit_modules

                    intersection.should_not be_empty
                  end
                end
              end
            end
          end

          context 'with stager' do
            let(:payload_type) do
              'stager'
            end

            context 'with no compatible stages' do
              it 'should contain no Classes' do
                expect { |block|
                  each_metasploit_class(&block)
                }.not_to yield_control
              end
            end

            context 'with compatible stages' do
              let!(:stage_module_ancestors) do
                FactoryGirl.create_list(
                    :mdm_module_ancestor,
                    2,
                    module_type: 'payload',
                    payload_type: 'stage'
                )
              end

              let!(:stage_metasploit_modules) do
                stage_module_ancestors.collect { |module_ancestor|
                  namespace = Module.new.tap do |namespace|
                    namespace.module_eval Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_CONTENT,
                                          Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_FILE,
                                          Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_LINE
                  end

                  namespace.module_type = module_ancestor.module_type
                  namespace.payload_type = module_ancestor.payload_type
                  namespace.real_path_sha1_hex_digest = module_ancestor.real_path_sha1_hex_digest

                  Msf::Modules.const_set("RealPathSha1HexDigest#{module_ancestor.real_path_sha1_hex_digest}", namespace)

                  namespace.module_ancestor_eval(module_ancestor)

                  namespace.metasploit_module
                }
              end

              before(:each) do
                architecture_abbreviations = self.architecture_abbreviations
                platform_fully_qualified_names = self.platform_fully_qualified_names

                [metasploit_module, *stage_metasploit_modules].each do |compatible_module|
                  compatible_module.send(:define_method, :arch) do
                    architecture_abbreviations
                  end

                  compatible_module.send(:define_method, :platform) do
                    platform_fully_qualified_names
                  end
                end
              end

              it 'should yield a Class for each compatible pair' do
                count = 0

                each_metasploit_class do |metasploit_class|
                  metasploit_class.should be_a Class
                  count += 1
                end

                count.should == stage_module_ancestors.length
              end

              context 'metasploit_classes' do
                subject(:metasploit_classes) do
                  each_metasploit_class
                end

                it 'should be subclasses of Msf::Payload' do
                  each_metasploit_class do |metasploit_class|
                    expect(metasploit_class).to be < Msf::Payload
                  end
                end

                it 'should include this metasploit module' do
                  each_metasploit_class do |metasploit_class|
                    metasploit_class.should include(metasploit_module)
                  end
                end

                it 'should include handler_module' do
                  each_metasploit_class do |metasploit_class|
                    metasploit_class.should include(metasploit_module.handler_module)
                  end
                end

                it 'should include metasploit module from stage' do
                  each_metasploit_class do |metasploit_class|
                    intersection = metasploit_class.ancestors & stage_metasploit_modules

                    intersection.should_not be_empty
                  end
                end
              end
            end
          end
        end
      end

      context 'without payload' do
        let(:module_type) do
          FactoryGirl.generate :metasploit_model_non_payload_module_type
        end

        let(:payload_type) do
          nil
        end

        it 'should contain only the metasploit_module itself because it is a Class already' do
          expect(each_metasploit_class.to_a).to match_array([metasploit_module])
        end

        context 'metasploit_class' do
          subject(:metasploit_class) do
            each_metasploit_class.first
          end

          it { should be_a Metasploit::Framework::Module::Class::MetasploitClass }
          it { should include(Metasploit::Framework::Module::Instance::MetasploitInstance) }
        end
      end
    end
  end

  context '#each_paired_metasploit_module' do
    # no subject() because block needs to be passed
    def each_paired_metasploit_module(&block)
      metasploit_module.each_paired_metasploit_module(&block)
    end

    let(:module_class) do
      FactoryGirl.build(
          :mdm_module_class,
          module_type: 'payload',
          payload_type: 'staged'
      )
    end

    it 'should call #paired_real_path_sha1_hex_digests' do
      metasploit_module.should_receive(:paired_real_path_sha1_hex_digests).and_return([])

      each_paired_metasploit_module { }
    end

    context '#paired_real_path_sha1_hex_digests' do
      before(:each) do
        metasploit_module.should_receive(
            :paired_real_path_sha1_hex_digests
        ).and_return(
            paired_real_path_sha1_hex_digests
        )
      end

      context 'with values' do
        include_context 'Metasploit::Framework::Spec::Constants cleaner'

        let(:paired_real_path_sha1_hex_digests) do
          2.times.collect { |n|
            Digest::SHA1.hexdigest("paired_real_path_sha1_hex_digest #{n}")
          }
        end

        context 'with defined' do
          let(:paired_namespace_modules) do
            paired_real_path_sha1_hex_digests.collect { |real_path_sha1_hex_digest|
              relative_name = "RealPathSha1HexDigest#{real_path_sha1_hex_digest}"

              namespace_module = double('Namespace Module')
              Msf::Modules.const_set relative_name, namespace_module
            }
          end

          let!(:paired_metasploit_modules) do
            paired_namespace_modules.collect { |namespace_module|
              metasploit_module = double('metasploit_module')
              namespace_module.should_receive(:metasploit_module).and_return(metasploit_module)

              metasploit_module
            }
          end

          it 'should yield defined metasploit modules' do
            expect { |block|
              each_paired_metasploit_module(&block)
            }.to yield_successive_args(*paired_metasploit_modules)
          end
        end

        context 'without defined' do
          specify {
            expect { |block|
              each_paired_metasploit_module(&block)
            }.not_to yield_control
          }
        end
      end

      context 'without values' do
        let(:paired_real_path_sha1_hex_digests) do
          []
        end

        specify {
          expect { |block|
            each_paired_metasploit_module(&block)
          }.not_to yield_control
        }
      end
    end
  end

  context '#each_staged_payload_class' do
    def each_staged_payload_class(&block)
      metasploit_module.each_staged_payload_class(&block)
    end

    let(:module_class) do
      FactoryGirl.build(
          :mdm_module_class,
          module_type: 'payload',
          payload_type: 'staged'
      )
    end

    it 'should call #each_compatible_metasploit_module' do
      metasploit_module.should_receive(:each_compatible_metasploit_module)

      each_staged_payload_class { }
    end

    context '#each_compatible_metasploit_module' do
      before(:each) do
        expectation = metasploit_module.should_receive(:each_compatible_metasploit_module)

        compatible_metasploit_modules.inject(expectation) do |expectation, compatible_metasploit_module|
          expectation.and_yield(compatible_metasploit_module)
        end
      end

      context 'with compatible metasploit modules' do
        let(:compatible_metasploit_modules) do
          2.times.collect { |n|
            name = "compatible_metasploit_module #{n}"
            real_path_sha1_hex_digest = Digest::SHA1.hexdigest(name)

            Module.new {
              extend Metasploit::Framework::Module::Ancestor::Handler
            }.tap { |m|
              m.stub(real_path_sha1_hex_digest: real_path_sha1_hex_digest)
            }
          }
        end

        context '#payload_type' do
          include_context 'Metasploit::Framework::Spec::Constants cleaner'

          let(:module_class_module_ancestor) do
            module_class.ancestors.find { |ancestor|
              ancestor.payload_type == payload_type
            }
          end

          context 'with stage' do
            let(:payload_type) do
              'stage'
            end

            let(:relative_names) do
              compatible_metasploit_modules.collect { |compatible_metasploit_module|
                "RealPathSha1HexDigest#{metasploit_module.real_path_sha1_hex_digest}StagedByRealPathSha1HexDigest#{compatible_metasploit_module.real_path_sha1_hex_digest}"
              }
            end

            context 'with constant defined' do
              let(:staged_payload_class_by_relative_name) do
                relative_names.each_with_object({}) { |relative_name, hash|
                  hash[relative_name] = Class.new
                }
              end

              let(:staged_payload_classes) do
                staged_payload_class_by_relative_name.values
              end

              before(:each) do
                staged_payload_class_by_relative_name.each do |relative_name, staged_payload_class|
                  Msf::Payloads.const_set relative_name, staged_payload_class
                end
              end

              it 'should return the defined constants' do
                yielded = []

                each_staged_payload_class { |staged_payload_class|
                  yielded << staged_payload_class
                }

                expect(yielded).to match_array(staged_payload_classes)
              end

              it 'should yield cachable classes' do
                staged_payload_classes.each do |staged_payload_class|
                  metasploit_module.should_receive(:cacheable_metasploit_class).with(staged_payload_class)
                end

                each_staged_payload_class { }
              end
            end

            context 'without constant defined' do
              it 'should get handler_module from compatible metasploit module' do
                compatible_metasploit_modules.each do |compatible_metasploit_module|
                  compatible_metasploit_module.should_receive(:handler_module).and_call_original
                end

                each_staged_payload_class { }
              end

              it 'should yield cachable classes' do
                compatible_metasploit_modules.each do
                  metasploit_module.should_receive(:cacheable_metasploit_class) do |klass|
                    klass.should be < Msf::Payload
                  end
                end

                each_staged_payload_class { }
              end

              it 'should include the stage, stager, and finally handler' do
                each_staged_payload_class { |staged_payload_class|
                  ancestors = staged_payload_class.ancestors

                  stage_index = ancestors.index(metasploit_module)

                  stager = compatible_metasploit_modules.find { |compatible_metasploit_module|
                    ancestors.include? compatible_metasploit_module
                  }

                  stager.should_not be_nil

                  stager_index = ancestors.index(stager)
                  handler_index = ancestors.index(stager.handler_module)

                  # a latter call to include means a closer ancestor and a lower index
                  handler_index.should be < stager_index
                  stager_index.should be < stage_index
                }
              end

              it 'should set constant' do
                each_staged_payload_class { }

                inherit = false

                relative_names.each do |relative_name|
                  Msf::Payloads.const_defined?(relative_name, inherit).should be_true
                end
              end
            end
          end

          context 'with stager' do
            let(:payload_type) do
              'stager'
            end

            let(:relative_names) do
              compatible_metasploit_modules.collect { |compatible_metasploit_module|
                "RealPathSha1HexDigest#{compatible_metasploit_module.real_path_sha1_hex_digest}StagedByRealPathSha1HexDigest#{metasploit_module.real_path_sha1_hex_digest}"
              }
            end

            context 'with constant defined' do
              let(:staged_payload_class_by_relative_name) do
                relative_names.each_with_object({}) { |relative_name, hash|
                  hash[relative_name] = Class.new
                }
              end

              let(:staged_payload_classes) do
                staged_payload_class_by_relative_name.values
              end

              before(:each) do
                staged_payload_class_by_relative_name.each do |relative_name, staged_payload_class|
                  Msf::Payloads.const_set relative_name, staged_payload_class
                end
              end

              it 'should return the defined constants' do
                yielded = []

                each_staged_payload_class { |staged_payload_class|
                  yielded << staged_payload_class
                }

                expect(yielded).to match_array(staged_payload_classes)
              end

              it 'should yield cachable classes' do
                staged_payload_classes.each do |staged_payload_class|
                  metasploit_module.should_receive(:cacheable_metasploit_class).with(staged_payload_class)
                end

                each_staged_payload_class { }
              end
            end

            context 'without constant defined' do
              it 'should get handler_module from this metasploit module' do
                metasploit_module.should_receive(:handler_module).exactly(
                    compatible_metasploit_modules.length
                ).times.and_call_original

                each_staged_payload_class { }
              end

              it 'should yield cachable classes' do
                compatible_metasploit_modules.each do
                  metasploit_module.should_receive(:cacheable_metasploit_class) do |klass|
                    klass.should be < Msf::Payload
                  end
                end

                each_staged_payload_class { }
              end

              it 'should include the stage, stager, and finally handler' do
                each_staged_payload_class { |staged_payload_class|
                  ancestors = staged_payload_class.ancestors

                  stage = compatible_metasploit_modules.find { |compatible_metasploit_module|
                    ancestors.include? compatible_metasploit_module
                  }

                  stage.should_not be_nil

                  stage_index = ancestors.index(stage)

                  stager_index = ancestors.index(metasploit_module)
                  handler_index = ancestors.index(metasploit_module.handler_module)

                  # a latter call to include means a closer ancestor and a lower index
                  handler_index.should be < stager_index
                  stager_index.should be < stage_index
                }
              end

              it 'should set constant' do
                each_staged_payload_class { }

                inherit = false

                relative_names.each do |relative_name|
                  Msf::Payloads.const_defined?(relative_name, inherit).should be_true
                end
              end
            end
          end
        end
      end

      context 'without compatible metasploit modules' do
        let(:compatible_metasploit_modules) do
          []
        end

        specify {
          expect { |block|
            each_staged_payload_class(&block)
          }.not_to yield_control
        }
      end
    end
  end

  context '#is_usable' do
    subject(:is_usable) do
      metasploit_module.is_usable
    end

    it { should be_true }
  end

  context '#module_type' do
    subject(:module_type) do
      metasploit_module.module_type
    end

    let(:parent) do
      double('Namespace Module', module_type: expected_module_type)
    end

    let(:expected_module_type) do
      FactoryGirl.generate :metasploit_model_module_type
    end

    before(:each) do
      metasploit_module.stub(parent: parent)
    end

    it 'should delegate to #parent' do
      module_type.should == parent.module_type
    end
  end

  context '#paired_payload_type' do
    subject(:paired_payload_type) do
      metasploit_module.paired_payload_type
    end

    context '#payload_type' do
      before(:each) do
        metasploit_module.stub(payload_type: payload_type)
      end

      context 'with single' do
        let(:payload_type) do
          'single'
        end

        specify {
          expect {
            paired_payload_type
          }.to raise_error(KeyError)
        }
      end

      context 'with stage' do
        let(:payload_type) do
          'stage'
        end

        it { should == 'stager' }
      end

      context 'with stager' do
        let(:payload_type) do
          'stager'
        end

        it { should == 'stage' }
      end

      context 'with nil' do
        let(:payload_type) do
          nil
        end

        specify {
          expect {
            paired_payload_type
          }.to raise_error(KeyError)
        }
      end
    end
  end

  context '#paired_real_path_sha1_hex_digests' do
    subject(:paired_real_path_sha1_hex_digests) do
      metasploit_module.paired_real_path_sha1_hex_digests
    end

    let(:payload_type) do
      ['stage', 'stager'].sample
    end

    before(:each) do
      metasploit_module.stub(payload_type: payload_type)
    end

    it 'should use #paired_payload_type' do
      metasploit_module.should_receive(:paired_payload_type)

      paired_real_path_sha1_hex_digests
    end

    context 'with Mdm::Module::Ancestors' do
      let!(:real_path_sha1_hex_digest_by_payload_type) do
        Metasploit::Model::Module::Ancestor::PAYLOAD_TYPES.each_with_object({}) do |payload_type, real_path_sha1_hex_digest_by_payload_type|
          module_ancestor = FactoryGirl.create(
              :mdm_module_ancestor,
              module_type: 'payload',
              payload_type: payload_type
          )

          real_path_sha1_hex_digest_by_payload_type[payload_type] = module_ancestor.real_path_sha1_hex_digest
        end
      end

      before(:each) do
        Metasploit::Model::Module::Type::NON_PAYLOAD.each do |module_type|
          FactoryGirl.create(:mdm_module_ancestor, module_type: module_type)
        end
      end

      context '#payload_type' do
        context 'with stage' do
          let(:payload_type) do
            'stage'
          end

          it 'should return Mdm::Module::Ancestor#real_path_sha1_hex_digest for stagers' do
            stager_real_path_sha1_hex_digests = Array.wrap(real_path_sha1_hex_digest_by_payload_type['stager'])

            expect(paired_real_path_sha1_hex_digests).to match_array(stager_real_path_sha1_hex_digests)
          end
        end

        context 'with stager' do
          let(:payload_type) do
            'stager'
          end

          it 'should return Mdm::Module::Ancestor#real_path_sha1_hex_digest for stages' do
            stage_real_path_sha1_hex_digests = Array.wrap(real_path_sha1_hex_digest_by_payload_type['stage'])

            pending "Sometimes `paired_real_path_sha1_hex_digest` has two entries for unknown reason"
            expect(paired_real_path_sha1_hex_digests).to match_array(stage_real_path_sha1_hex_digests)
          end
        end
      end
    end

    context 'without Mdm::Module::Ancestors' do
      it { should be_empty }
    end
  end

  context '#payload_metasploit_class' do
    subject(:payload_metasploit_class) do
      metasploit_module.payload_metasploit_class
    end

    let(:module_ancestor_payload_type) do
      case module_class_payload_type
        when 'single'
          'single'
        when 'staged'
          ['stage', 'stager'].sample
        when nil
          nil
      end
    end

    let(:module_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: module_type,
          payload_type: module_class_payload_type
      )
    end

    let(:module_class_module_ancestor) do
      module_class.ancestors.find { |module_ancestor|
        module_ancestor.module_type == module_type &&
        module_ancestor.payload_type == module_ancestor_payload_type
      }
    end

    let(:module_class_payload_type) do
      case module_type
        when 'payload'
          Metasploit::Model::Module::Class::PAYLOAD_TYPES.sample
        else
          nil
      end
    end

    let(:module_type) do
      'payload'
    end

    context '#module_type' do
      context 'with payload' do
        let(:module_type) do
          'payload'
        end

        context '#payload_type' do
          include_context 'Metasploit::Framework::Spec::Constants cleaner'

          let(:relative_name) do
            "RealPathSha1HexDigest#{metasploit_module.real_path_sha1_hex_digest}"
          end

          context 'single' do
            let(:module_class_payload_type) do
              'single'
            end

            let(:module_ancestor_payload_type) do
              'single'
            end

            context 'with constant defined' do
              let(:expected_payload_metasploit_class) do
                Class.new
              end

              before(:each) do
                Msf::Payloads.const_set relative_name, expected_payload_metasploit_class
              end

              it 'should return constant' do
                payload_metasploit_class.should == expected_payload_metasploit_class
              end

              it 'should return a cacheable class' do
                metasploit_module.should_receive(:cacheable_metasploit_class).with(expected_payload_metasploit_class)

                payload_metasploit_class
              end
            end

            context 'without constant defined' do
              it 'should be a subclass of Msf::Payload' do
                payload_metasploit_class.should be < Msf::Payload
              end

              it 'should include this metasploit module and then the handler' do
                ancestors = payload_metasploit_class.ancestors
                self_index = ancestors.index(metasploit_module)
                handler_index = ancestors.index(metasploit_module.handler_module)

                # later includes have lower ancestor index since they're nearer
                handler_index.should be < self_index
              end

              it 'should set constant' do
                payload_metasploit_class

                Msf::Payloads.const_defined?(relative_name).should be_true
              end

              it 'should return a cacheable class' do
                metasploit_module.should_receive(:cacheable_metasploit_class) do |klass|
                  klass.should be < Msf::Payload
                end

                payload_metasploit_class
              end
            end
          end

          context 'stage' do
            let(:module_ancestor_payload_type) do
              'stage'
            end

            let(:module_class_payload_type) do
              'staged'
            end

            context 'with constant defined' do
              let(:expected_payload_metasploit_class) do
                Class.new
              end

              before(:each) do
                Msf::Payloads.const_set relative_name, expected_payload_metasploit_class
              end

              it 'should return constant' do
                payload_metasploit_class.should == expected_payload_metasploit_class
              end

              it 'should return a cacheable class' do
                metasploit_module.should_receive(:cacheable_metasploit_class).with(expected_payload_metasploit_class)

                payload_metasploit_class
              end
            end

            context 'without constant defined' do
              it 'should be a subclass of Msf::Payload' do
                payload_metasploit_class.should be < Msf::Payload
              end

              it 'should include this metasploit module, Metasploit::Framwork::Module::Ancestor::Payload::Stage::Handler and then its handler module' do
                ancestors = payload_metasploit_class.ancestors
                self_index = ancestors.index(metasploit_module)
                payload_stage_handler_index = ancestors.index(Metasploit::Framework::Module::Ancestor::Payload::Stage::Handler)
                handler_index = ancestors.index(Metasploit::Framework::Module::Ancestor::Payload::Stage::Handler.handler_module)

                # later includes have lower ancestor index since they're nearer
                payload_stage_handler_index.should be < self_index
                handler_index.should be < payload_stage_handler_index
              end

              it 'should set constant' do
                payload_metasploit_class

                Msf::Payloads.const_defined?(relative_name).should be_true
              end

              it 'should return a cacheable class' do
                metasploit_module.should_receive(:cacheable_metasploit_class) do |klass|
                  klass.should be < Msf::Payload
                end

                payload_metasploit_class
              end
            end
          end

          context 'stager' do
            let(:module_ancestor_payload_type) do
              'stager'
            end

            let(:module_class_payload_type) do
              'staged'
            end

            context 'with constant defined' do
              let(:expected_payload_metasploit_class) do
                Class.new
              end

              before(:each) do
                Msf::Payloads.const_set relative_name, expected_payload_metasploit_class
              end

              it 'should return constant' do
                payload_metasploit_class.should == expected_payload_metasploit_class
              end

              it 'should return a cacheable class' do
                metasploit_module.should_receive(:cacheable_metasploit_class).with(expected_payload_metasploit_class)

                payload_metasploit_class
              end
            end

            context 'without constant defined' do
              it 'should be a subclass of Msf::Payload' do
                payload_metasploit_class.should be < Msf::Payload
              end

              it 'should include this metasploit module  and then its handler module' do
                ancestors = payload_metasploit_class.ancestors
                self_index = ancestors.index(metasploit_module)
                handler_index = ancestors.index(metasploit_module.handler_module)

                # later includes have lower ancestor index since they're nearer
                handler_index.should be < self_index
              end

              it 'should set constant' do
                payload_metasploit_class

                Msf::Payloads.const_defined?(relative_name).should be_true
              end

              it 'should return a cacheable class' do
                metasploit_module.should_receive(:cacheable_metasploit_class) do |klass|
                  klass.should be < Msf::Payload
                end

                payload_metasploit_class
              end
            end
          end
        end
      end

      context 'without payload' do
        let(:module_type) do
          Metasploit::Model::Module::Type::NON_PAYLOAD.sample
        end

        specify {
          expect {
            payload_metasploit_class
          }.to raise_error(ArgumentError)
        }
      end
    end
  end

  context '#payload_type' do
    subject(:payload_type) do
      metasploit_module.payload_type
    end

    let(:parent) do
      double('Namespace Module', payload_type: expected_payload_type)
    end

    let(:expected_payload_type) do
      FactoryGirl.generate :metasploit_model_module_ancestor_payload_type
    end

    before(:each) do
      metasploit_module.stub(parent: parent)
    end

    it 'should delegate to #parent' do
      payload_type.should == parent.payload_type
    end
  end

  context '#real_path_sha1_hex_digest' do
    subject(:real_path_sha1_hex_digest) do
      metasploit_module.real_path_sha1_hex_digest
    end

    let(:parent) do
      double('Namespace Module', real_path_sha1_hex_digest: expected_real_path_sha1_hex_digest)
    end

    let(:expected_real_path_sha1_hex_digest) do
      Digest::SHA1.new.tap { |d| d << 'parent' }.hexdigest
    end

    before(:each) do
      metasploit_module.stub(parent: parent)
    end

    it 'should delegate to #parent' do
      real_path_sha1_hex_digest.should == parent.real_path_sha1_hex_digest
    end
  end

  context '#validation_proxy_class' do
    subject(:validation_proxy_class) do
      metasploit_module.validation_proxy_class
    end

    it { should == Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy }
  end
end