shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache' do
  context '#cache_module_instance' do
    subject(:cache_module_instance) do
      base_instance.cache_module_instance(module_instance)
    end

    let(:module_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: module_type,
          payload_type: payload_type
      )
    end

    let(:module_instance) do
      module_class.build_module_instance
    end

    let(:payload_type) do
      nil
    end

    context '#module_type' do
      def build_expected_module_actions(module_instance)
        action_count = Random.rand(1 .. 3)

        actions = action_count.times.collect {
          FactoryGirl.build(:mdm_module_action, module_instance: module_instance)
        }
        module_instance.actions = actions
        module_instance.default_action = actions.sample
      end

      def build_expected_module_architectures(module_instance)
        architectures = architecture_count.times.collect {
          FactoryGirl.generate :mdm_architecture
        }

        module_instance.module_architectures = architectures.collect do |architecture|
          FactoryGirl.build(
              :mdm_module_architecture,
              architecture: architecture,
              module_instance: module_instance
          )
        end
      end

      def build_expected_module_authors(module_instance)
        full_module_author = FactoryGirl.build(:full_mdm_module_author, module_instance: module_instance)
        # validate to derive full
        full_module_author.valid?
        module_instance.module_authors << full_module_author

        module_author = FactoryGirl.build(:mdm_module_author, module_instance: module_instance)
        # validate to derive full
        module_author.valid?
        module_instance.module_authors << module_author
      end

      def build_expected_module_platforms(module_instance)
        module_instance.module_platforms = platform_count.times.collect {
          FactoryGirl.build(
              :mdm_module_platform,
              module_instance: module_instance
          )
        }
      end

      def build_expected_module_references(module_instance)
        expected_references.each do |reference|
          module_instance.module_references.build(
              reference: reference
          )
        end
      end

      #
      # lets
      #

      let(:architecture_count) do
        Random.rand(1 .. 3)
      end

      let(:expected_module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            actions_length: 0,
            module_class: module_class,
            module_architectures_length: 0,
            module_authors_length: 0,
            module_platforms_length: 0,
            module_references_length: 0,
            targets_length: 0
        ).tap { |module_instance|
          build_expected_module_authors(module_instance)
        }
      end

      let(:expected_references) do
        # MUST use seeded_authority_mdm_reference and not mdm_reference or expected reference will have a URL that
        # cannot be parsed back from the base_instance
        factories = [:obsolete_mdm_reference, :seeded_authority_mdm_reference, :url_mdm_reference]

        factories.collect { |factory|
          FactoryGirl.build(factory).tap { |reference|
            # validate so that url is derived from authority when necessary
            reference.valid?
          }
        }
      end

      let(:formatted_actions) do
        expected_module_instance.actions.collect { |action|
          # Array format of {Msf::Module::AuxiliaryAction} is [name <,{ 'Description' => description, **}>]
          [action.name]
        }
      end

      let(:formatted_architectures) do
        expected_module_instance.module_architectures.collect { |module_architecture|
          module_architecture.architecture.abbreviation
        }
      end

      let(:formatted_authors) do
        expected_module_instance.module_authors.collect { |module_author|
          author = Msf::Module::Author.new
          author.name = module_author.author.name

          email_address = module_author.email_address

          if email_address
            author.email = email_address.full
          end

          author.to_s
        }
      end

      let(:formatted_default_action) do
        expected_module_instance.default_action.name
      end

      let(:formatted_platforms) do
        expected_module_instance.module_platforms.collect { |module_platform|
          module_platform.platform.fully_qualified_name
        }
      end

      let(:formatted_references) do
        expected_module_instance.module_references.collect { |module_reference|
          reference = module_reference.reference

          if reference.authority?
            [reference.authority.abbreviation, reference.designation]
          else
            ['URL', reference.url]
          end
        }
      end

      let(:platform_count) do
        Random.rand(1 .. 3)
      end

      context 'with auxiliary' do
        let(:base_class) do
          described_class = self.described_class
          expected_module_instance = self.expected_module_instance
          formatted_actions = self.formatted_actions
          formatted_authors = self.formatted_authors
          formatted_default_action = self.formatted_default_action
          formatted_references = self.formatted_references

          Class.new(Msf::Auxiliary) do
            include described_class

            define_method(:initialize) do |attributes={}|
              super(
                  update_info(
                      attributes,
                      'Actions' => formatted_actions,
                      'Author' => formatted_authors,
                      'Description' => expected_module_instance.description,
                      'DefaultAction' => formatted_default_action,
                      'License' => expected_module_instance.license,
                      'Name' => expected_module_instance.name,
                      'References' => formatted_references
                  )
              )
            end
          end
        end

        let(:expected_module_instance) do
          super().tap { |module_instance|
            build_expected_module_actions(module_instance)
            build_expected_module_references(module_instance)
          }
        end

        let(:module_type) do
          'auxiliary'
        end

        it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance'

        context 'Mdm::Module::Instance' do
          subject(:actual_module_instance) do
            cache_module_instance
          end

          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance'

          context '#actions' do
            subject(:actions) do
              actual_module_instance.actions
            end

            it 'should match Msf::Module#actions' do
              expected_action_names = expected_module_instance.actions.map(&:name)
              actual_action_names = actions.map(&:name)

              expect(actual_action_names).to match_array(expected_action_names)
            end

            it 'should be persisted' do
              actions.all?(&:persisted?).should be_true
            end
          end

          context '#default_action' do
            subject(:default_action) do
              actual_module_instance.default_action
            end

            it 'should match Msf::Module#default_action' do
              default_action.name.should == expected_module_instance.default_action.name
            end
          end

          context '#module_architectures' do
            subject(:module_architectures) do
              actual_module_instance.module_architectures
            end

            it { should be_empty }
          end

          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_references'
        end
      end

      context 'with encoder' do
        let(:base_class) do
          described_class = self.described_class
          expected_module_instance = self.expected_module_instance
          formatted_authors = self.formatted_authors
          formatted_architectures = self.formatted_architectures

          Class.new(Msf::Encoder) do
            include described_class

            define_method(:initialize) do |attributes={}|
              super(
                  update_info(
                      attributes,
                      'Arch' => formatted_architectures,
                      'Author' => formatted_authors,
                      'Description' => expected_module_instance.description,
                      'License' => expected_module_instance.license,
                      'Name' => expected_module_instance.name
                  )
              )
            end
          end
        end

        let(:expected_module_instance) do
          super().tap { |module_instance|
            build_expected_module_architectures(module_instance)
          }
        end

        let(:module_type) do
          'encoder'
        end

        it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance'

        context 'Mdm::Module::Instance' do
          subject(:actual_module_instance) do
            cache_module_instance
          end

          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance'
          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_architectures'
        end
      end

      context 'with exploit' do
        def build_expected_targets(module_instance)
          target_count = Random.rand(1 .. 3)

          target_count.times do
            # module_target factory will populate module_architectures and module_platforms from targets
            FactoryGirl.build(
                :mdm_module_target,
                module_instance: module_instance
            )
          end
        end

        #
        # lets
        #

        let(:base_class) do
          described_class = self.described_class
          expected_module_instance = self.expected_module_instance
          expected_default_target = self.expected_default_target
          formatted_authors = self.formatted_authors
          formatted_references = self.formatted_references
          formatted_targets = self.formatted_targets

          Class.new(Msf::Exploit) {
            include described_class

            define_method(:initialize) do |attributes={}|
              super(
                  update_info(
                      attributes,
                      'Author' => formatted_authors,
                      'DefaultTarget' => expected_default_target,
                      'Description' => expected_module_instance.description,
                      'License' => expected_module_instance.license,
                      'Name' => expected_module_instance.name,
                      'References' => formatted_references,
                      'Targets' => formatted_targets
                  )
              )
            end
          }
        end

        let(:expected_default_target) do
          Random.rand(0 ... formatted_targets.length)
        end

        let(:expected_module_instance) do
          super().tap { |module_instance|
            build_expected_module_references(module_instance)
            build_expected_targets(module_instance)
          }
        end

        let(:formatted_targets) do
          expected_module_instance.targets.collect { |target|
            formatted_target_architectures = target.target_architectures.collect { |target_architecture|
              target_architecture.architecture.abbreviation
            }

            formatted_target_platforms = target.target_platforms.collect { |target_platform|
              target_platform.platform.fully_qualified_name
            }

            [
                target.name,
                {
                    'Arch' => formatted_target_architectures,
                    'Platform' => formatted_target_platforms
                }
            ]
          }
        end

        let(:module_type) do
          'exploit'
        end

        it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance'

        context 'Mdm::Module::Instance' do
          subject(:actual_module_instance) do
            cache_module_instance
          end

          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance'

          context '#module_architectures' do
            subject(:actual_module_architectures) do
              actual_module_instance.module_architectures
            end

            context 'architectures' do
              subject(:actual_architectures) do
                actual_module_architectures.map(&:architecture)
              end

              let(:expected_architecture_set) do
                expected_module_instance.targets.each_with_object(Set.new) { |module_target, set|
                  module_target.target_architectures.each do |target_architecture|
                    set.add target_architecture.architecture
                  end
                }
              end

              it 'should be contain all target architectures' do
                expected_architectures = expected_architecture_set.to_a
                expect(actual_architectures).to match_array(expected_architectures)
              end
            end
          end

          context '#module_platforms' do
            subject(:actual_module_platforms) do
              actual_module_instance.module_platforms
            end

            context 'platforms' do
              subject(:actual_platforms) do
                actual_module_platforms.map(&:platform)
              end

              let(:expected_platform_set) do
                expected_module_instance.targets.each_with_object(Set.new) { |module_target, set|
                  module_target.target_platforms.each do |target_platform|
                    set.add target_platform.platform
                  end
                }
              end

              it 'should be contain all target platforms' do
                expected_platforms = expected_platform_set.to_a
                expect(actual_platforms).to match_array(expected_platforms)
              end
            end
          end

          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_references'
        end
      end

      context 'with nop' do
        let(:base_class) do
          described_class = self.described_class
          expected_module_instance = self.expected_module_instance
          formatted_authors = self.formatted_authors
          formatted_architectures = self.formatted_architectures

          Class.new(Msf::Exploit) do
            include described_class

            define_method(:initialize) do |attributes={}|
              super(
                  update_info(
                      attributes,
                      'Arch' => formatted_architectures,
                      'Author' => formatted_authors,
                      'Description' => expected_module_instance.description,
                      'License' => expected_module_instance.license,
                      'Name' => expected_module_instance.name
                  )
              )
            end
          end
        end

        let(:expected_module_instance) do
          super().tap { |module_instance|
            build_expected_module_architectures(module_instance)
          }
        end

        let(:module_type) do
          'nop'
        end

        it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance'

        context 'Mdm::Module::Instance' do
          subject(:actual_module_instance) do
            cache_module_instance
          end

          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance'
          it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_architectures'
        end
      end

      context 'with payload' do
        let(:base_class) do
          described_class = self.described_class

          Class.new(Msf::Payload) do
            include described_class
          end
        end

        let(:expected_module_instance) do
          super().tap { |module_instance|
            build_expected_module_architectures(module_instance)
            build_expected_module_platforms(module_instance)
            build_expected_module_references(module_instance)
          }
        end

        let(:module_type) do
          'payload'
        end

        context '#payload_type' do
          context 'with single' do
            let(:base_class) do
              super().tap { |klass|
                klass.send(:include, single_payload_module)
                klass.send(:include, single_payload_module.handler_module)
              }
            end

            let(:payload_type) do
              'single'
            end

            let(:single_payload_module) do
              # ActiveSupport::Dependencies can't autoload handlers, so need explicit require
              require 'msf/core/handler/bind_tcp'

              expected_module_instance = self.expected_module_instance
              formatted_architectures = self.formatted_architectures
              formatted_authors = self.formatted_authors
              formatted_platforms = self.formatted_platforms

              Module.new {
                extend Metasploit::Framework::Module::Ancestor::Handler

                include Msf::Payload::Single

                # chosen only because it's the first handler
                handler module_name: 'Msf::Handler::BindTcp'

                define_method(:initialize) do |attributes={}|
                  super(
                      update_info(
                          attributes,
                          'Arch' => formatted_architectures,
                          'Author' => formatted_authors,
                          'Description' => expected_module_instance.description,
                          'License' => expected_module_instance.license,
                          'Name' => expected_module_instance.name,
                          'Platform' => formatted_platforms
                      )
                  )
                end
              }
            end

            it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance'

            context 'Mdm::Module::Instance' do
              subject(:actual_module_instance) do
                cache_module_instance
              end

              it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance'
              it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_architectures'
              it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_platforms'
            end
          end

          context 'with staged' do
            let(:architecture_count) do
              # ensure there are at least 2 architectures so stage and stager can have at least one
              Random.rand(2 .. 5)
            end

            let(:base_class) do
              super().tap { |klass|
                klass.send(:include, stage_payload_module)
                klass.send(:include, stager_payload_module)
                klass.send(:include, stager_payload_module.handler_module)
              }
            end

            let(:expected_module_instance) do
              super().tap { |module_instance|
                module_instance.description = "#{stage_description}, #{stager_description}"
                module_instance.name = "#{stager_name}, #{stage_name}"
              }
            end

            let(:payload_type) do
              'staged'
            end

            let(:platform_count) do
              # ensure there are at least 2 platforms so stage and stager can have at least one
              Random.rand(2 .. 5)
            end

            let(:stage_description) do
              FactoryGirl.generate :metasploit_model_module_instance_description
            end

            let(:stage_formatted_architectures) do
              # at least one, but not all, so stager can have at least one
              size = Random.rand(1 ... formatted_architectures.length)
              formatted_architectures.sample(size)
            end

            let(:stage_formatted_authors) do
              # at least one, but not all, so stager can have at least one
              size = Random.rand(1 ... formatted_authors.length)
              formatted_authors.sample(size)
            end

            let(:stage_formatted_platforms) do
              # at least one, but not all, so stager can have at least one
              size = Random.rand(1 ... formatted_platforms.length)
              formatted_platforms.sample(size)
            end

            let(:stage_license) do
              FactoryGirl.generate :metasploit_model_module_instance_license
            end

            let(:stage_name) do
              FactoryGirl.generate :metasploit_model_module_instance_name
            end

            let(:stage_payload_module) do
              stage_description = self.stage_description
              stage_formatted_architectures = self.stage_formatted_architectures
              stage_formatted_authors = self.stage_formatted_authors
              stage_formatted_platforms = self.stage_formatted_platforms
              stage_license = self.stage_license
              stage_name = self.stage_name

              Module.new {
                define_method(:initialize) do |options={}|
                  super(
                      # stage must use merge and not update so that stager name and description is merged with stage
                      # name and description.
                      merge_info(
                          options,
                          'Arch' => stage_formatted_architectures,
                          'Author' => stage_formatted_authors,
                          'Description' => stage_description,
                          'License' => stage_license,
                          'Name' => stage_name,
                          'Platform' => stage_formatted_platforms
                      )
                  )
                end
              }
            end

            let(:stager_description) do
              FactoryGirl.generate :metasploit_model_module_instance_description
            end

            let(:stager_formatted_architectures) do
              formatted_architectures - stage_formatted_architectures
            end

            let(:stager_formatted_authors) do
              formatted_authors - stage_formatted_authors
            end

            let(:stager_formatted_platforms) do
              formatted_platforms - stage_formatted_platforms
            end

            let(:stager_license) do
              FactoryGirl.generate :metasploit_model_module_instance_license
            end

            let(:stager_name) do
              FactoryGirl.generate :metasploit_model_module_instance_name
            end

            let(:stager_payload_module) do
              require 'msf/core/handler/reverse_tcp'

              stager_description = self.stager_description
              stager_formatted_architectures = self.stager_formatted_architectures
              stager_formatted_authors = self.stager_formatted_authors
              stager_formatted_platforms = self.stager_formatted_platforms
              stager_license = self.stager_license
              stager_name = self.stager_name

              Module.new {
                extend Metasploit::Framework::Module::Ancestor::Handler

                include Msf::Payload::Stager

                # this specific module is not significant, just a define handler module that I happened to be looking at
                handler module_name: 'Msf::Handler::ReverseTcp'

                define_method(:initialize) do |options={}|
                  super(
                      # stager must use merge and not update
                      merge_info(
                          options,
                          'Arch' => stager_formatted_architectures,
                          'Author' => stager_formatted_authors,
                          'Description' => stager_description,
                          'License' => stager_license,
                          'Name' => stager_name,
                          'Platform' => stager_formatted_platforms
                      )
                  )
                end
              }
            end

            it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance'

            context 'Mdm::Module::Instance' do
              subject(:actual_module_instance) do
                cache_module_instance
              end

              pending 'https://www.pivotaltracker.com/story/show/60433512' do
                it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance'
              end

              it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_architectures'
              it_should_behave_like 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_platforms'
            end
          end
        end
      end
    end
  end
end