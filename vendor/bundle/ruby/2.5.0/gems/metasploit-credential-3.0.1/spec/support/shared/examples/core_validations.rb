RSpec.shared_examples_for 'Metasploit::Credential::CoreValidations' do

  #
  # Context Methods
  #

  # Returns correlation with the given `name` from options.
  #
  # @param options [Hash{Symbol => :different, :same}]
  # @param name [Symbol] name of correlation option in `options`.
  # @return [:different, :same]
  # @raise [ArgumentError] if `options[name]` is not `:different` or `:same`
  # @raise [KeyError] if `options` does not contain key `name`
  def self.correlation!(options, name)
    correlation = options.fetch(name)

    unless [:different, :same].include? correlation
      raise ArgumentError, "#{name} must be :different or :same"
    end

    correlation
  end

  # Declares a `context` with correlation on `name` and body of `block`
  #
  # @param options [Hash{Symbol => :different, :same}]
  # @param name [Symbol] name of correlation option in `options`.
  # @yield Block that functions as body of `context`
  # @return [void]
  # @raise (see correlation!)
  def self.context_with_correlation(options, name, &block)
    correlation = correlation!(options, name)

    context "with #{correlation} #{name}" do
      if correlation == :same
        let("second_#{name}") {
          send("first_#{name}")
        }
      end

      instance_eval(&block)
    end
  end

  #
  # Shared Contexts
  #

  shared_context 'two metasploit_credential_cores' do
    #
    # lets
    #

    let(:first_workspace) {
      FactoryBot.create(:mdm_workspace)
    }

    let(:origin) {
      # use an origin where the workspace does not need to correlate
      FactoryBot.create(:metasploit_credential_origin_manual)
    }

    let(:factory_name) {
      :metasploit_credential_core
    }

    let(:first_factory_options) {
      {
      origin: origin,
      private: first_private,
      public: first_public,
      realm: first_realm,
      workspace: first_workspace
      }
    }

    let(:second_factory_options) {
      {
          origin: origin,
          private: second_private,
          public: second_public,
          realm: second_realm,
          workspace: second_workspace
      }
    }

    let(:second_metasploit_credential_core) {
      FactoryBot.build( factory_name, second_factory_options)
    }

    #
    # let!s
    #

    let!(:first_metasploit_credential_core) {
      FactoryBot.create(factory_name, first_factory_options)
    }
  end

  context 'database' do
    context 'indices' do
      context 'foreign keys' do
        let(:first_private) {
          FactoryBot.create(:metasploit_credential_private)
        }

        let(:second_public) {
          FactoryBot.create(:metasploit_credential_username)
        }

        let(:second_private) {
          FactoryBot.create(:metasploit_credential_private)
        }

        let(:second_realm) {
          FactoryBot.create(:metasploit_credential_realm)
        }

        let(:second_workspace) {
          FactoryBot.create(:mdm_workspace)
        }

        shared_examples_for 'potential collision' do |options={}|
          options.assert_valid_keys(:collision, :index)

          if options.fetch(:collision)
            it 'raises ActiveRecord::RecordNotUnique' do
              expect {
                second_metasploit_credential_core.save(validate: false)
              }.to raise_error(ActiveRecord::RecordNotUnique) { |error|
                expect(error.message).to include(
                                             "duplicate key value violates unique constraint \"#{options.fetch(:index)}\""
                                         )
              }
            end
          else
            it 'does not raise ActiveRecord::RecordNotUnique' do
              expect {
                second_metasploit_credential_core.save(validate: false)
              }.not_to raise_error
            end
          end
        end

        shared_examples_for 'unique_private_metasploit_credential_cores' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :workspace)

          #
          # lets
          #

          let(:first_public) {
            nil
          }

          let(:first_realm) {
            nil
          }

          let(:second_public) {
            nil
          }

          let(:second_realm) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :private) do
              it_should_behave_like 'potential collision',
                                    collision: options.fetch(:collision),
                                    index: 'unique_private_metasploit_credential_cores'
            end
          end
        end

        shared_examples_for 'unique_public_metasploit_credential_cores' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :public, :workspace)

          #
          # lets
          #

          let(:first_private) {
            nil
          }

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            nil
          }

          let(:second_private) {
            nil
          }

          let(:second_realm) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :public) do
              it_should_behave_like 'potential collision',
                                    collision: options.fetch(:collision),
                                    index: 'unique_public_metasploit_credential_cores'
            end
          end
        end

        shared_examples_for 'unique_realmless_metasploit_credential_cores' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :public, :workspace)

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            nil
          }

          let(:second_realm) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :public) do
              context_with_correlation(options, :private) do
                it_should_behave_like 'potential collision',
                                      collision: options.fetch(:collision),
                                      index: 'unique_realmless_metasploit_credential_cores'
              end
            end
          end
        end

        shared_examples_for 'unique_publicless_metasploit_credential_cores' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :realm, :workspace)

          let(:first_public) {
            nil
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          let(:second_public) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :realm) do
              context_with_correlation(options, :private) do
                it_should_behave_like 'potential collision',
                                      collision: options.fetch(:collision),
                                      index: 'unique_publicless_metasploit_credential_cores'
              end
            end
          end
        end

        shared_examples_for 'unique_privateless_metasploit_credential_cores' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :public, :realm, :workspace)

          let(:first_private) {
            nil
          }

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          let(:second_private) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :realm) do
              context_with_correlation(options, :public) do
                it_should_behave_like 'potential collision',
                                      collision: options.fetch(:collision),
                                      index: 'unique_privateless_metasploit_credential_cores'
              end
            end
          end
        end

        shared_examples_for 'unique_complete_metasploit_credential_cores' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :public, :realm, :workspace)

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :realm) do
              context_with_correlation(options, :public) do
                context_with_correlation(options, :private) do
                  it_should_behave_like 'potential collision',
                                        collision: options.fetch(:collision),
                                        index: 'unique_complete_metasploit_credential_cores'
                end
              end
            end
          end
        end

        it_should_behave_like 'unique_private_metasploit_credential_cores',
                              workspace: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'unique_private_metasploit_credential_cores',
                              workspace: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_private_metasploit_credential_cores',
                              workspace: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_private_metasploit_credential_cores',
                              workspace: :different,
                              private: :different,
                              collision: false

        it_should_behave_like 'unique_public_metasploit_credential_cores',
                              workspace: :same,
                              public: :same,
                              collision: true
        it_should_behave_like 'unique_public_metasploit_credential_cores',
                              workspace: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'unique_public_metasploit_credential_cores',
                              workspace: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'unique_public_metasploit_credential_cores',
                              workspace: :different,
                              public: :different,
                              collision: false

        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :same,
                              public: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :same,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :same,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :same,
                              public: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :different,
                              public: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :different,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :different,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_realmless_metasploit_credential_cores',
                              workspace: :different,
                              public: :different,
                              private: :different,
                              collision: false

        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_publicless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              private: :different,
                              collision: false

        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              public: :same,
                              collision: true
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              public: :different,
                              collision: false
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              public: :same,
                              collision: false
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'unique_privateless_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              public: :different,
                              collision: false

        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              public: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :same,
                              public: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              public: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :same,
                              realm: :different,
                              public: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              public: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :same,
                              public: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              public: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'unique_complete_metasploit_credential_cores',
                              workspace: :different,
                              realm: :different,
                              public: :different,
                              private: :different,
                              collision: false
      end
    end

    context 'validations' do
      it { is_expected.to validate_presence_of :workspace }

      context 'of uniqueness' do
        let(:first_private) {
          FactoryBot.create(:metasploit_credential_private)
        }

        let(:second_public) {
          FactoryBot.create(:metasploit_credential_username)
        }

        let(:second_private) {
          FactoryBot.create(:metasploit_credential_private)
        }

        let(:second_realm) {
          FactoryBot.create(:metasploit_credential_realm)
        }

        let(:second_workspace) {
          FactoryBot.create(:mdm_workspace)
        }

        shared_examples_for 'potential collision' do |options={}|
          options.assert_valid_keys(:attribute, :collision, :message)

          subject {
            second_metasploit_credential_core
          }

          #
          # Callbacks
          #

          if options.fetch(:collision)
            it 'add validation error' do
              second_metasploit_credential_core.valid?


              expect(
                  second_metasploit_credential_core.errors[options.fetch(:attribute)]
              ).to include options.fetch(:message)
            end
          else
            it { is_expected.to be_valid }
          end
        end

        shared_examples_for 'on (workspace_id, realm_id, public_id, private_id) without realm_id without public_id' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :workspace)

          #
          # lets
          #

          let(:first_public) {
            nil
          }

          let(:first_realm) {
            nil
          }

          let(:second_public) {
            nil
          }

          let(:second_realm) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :private) do
              it_should_behave_like 'potential collision',
                                    attribute: :private_id,
                                    collision: options.fetch(:collision),
                                    message: 'is already taken for credential cores with only a private credential'
            end
          end
        end

        shared_examples_for 'on (workspace_id, realm_id, private_id, public_id) without realm_id without private_id' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :public, :workspace)

          #
          # lets
          #

          let(:first_private) {
            nil
          }

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            nil
          }

          let(:second_private) {
            nil
          }

          let(:second_realm) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :public) do
              it_should_behave_like 'potential collision',
                                    attribute: :public_id,
                                    collision: options.fetch(:collision),
                                    message: 'is already taken for credential cores with only a public credential'
            end
          end
        end

        shared_examples_for 'on (workspace_id, realm_id, public_id, private_id) without realm_id' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :public, :workspace)

          let(:first_realm) {
            nil
          }

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:second_realm) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :public) do
              context_with_correlation(options, :private) do
                it_should_behave_like 'potential collision',
                                      attribute: :private_id,
                                      collision: options.fetch(:collision),
                                      message: 'is already taken for credential cores without a credential realm'
              end
            end
          end
        end

        shared_examples_for 'on (workspace_id, realm_id, public_, private_id) without public_id' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :realm, :workspace)

          let(:first_public) {
            nil
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          let(:second_public) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :realm) do
              context_with_correlation(options, :private) do
                it_should_behave_like 'potential collision',
                                      attribute: :private_id,
                                      collision: options.fetch(:collision),
                                      message: 'is already taken for credential cores without a public credential'
              end
            end
          end
        end

        shared_examples_for 'on (workspace_id, realm_id, public_id, private_id) without private_id' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :public, :realm, :workspace)

          let(:first_private) {
            nil
          }

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          let(:second_private) {
            nil
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :realm) do
              context_with_correlation(options, :public) do
                it_should_behave_like 'potential collision',
                                      attribute: :public_id,
                                      collision: options.fetch(:collision),
                                      message: 'is already taken for credential cores without a private credential'
              end
            end
          end
        end

        shared_examples 'on (workspace_id, realm_id, public_id, private_id)' do |options={}|
          include_context 'two metasploit_credential_cores'

          options.assert_valid_keys(:collision, :private, :public, :realm, :workspace)

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          context_with_correlation(options, :workspace) do
            context_with_correlation(options, :realm) do
              context_with_correlation(options, :public) do
                context_with_correlation(options, :private) do
                  it_should_behave_like 'potential collision',
                                        attribute: :private_id,
                                        collision: options.fetch(:collision),
                                        message: 'is already taken for complete credential cores'
                end
              end
            end
          end
        end

        #
        # Examples
        #

        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id without public_id',
                              workspace: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id without public_id',
                              workspace: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id without public_id',
                              workspace: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id without public_id',
                              workspace: :different,
                              private: :different,
                              collision: false

        it_should_behave_like 'on (workspace_id, realm_id, private_id, public_id) without realm_id without private_id',
                              workspace: :same,
                              public: :same,
                              collision: true
        it_should_behave_like 'on (workspace_id, realm_id, private_id, public_id) without realm_id without private_id',
                              workspace: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, private_id, public_id) without realm_id without private_id',
                              workspace: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, private_id, public_id) without realm_id without private_id',
                              workspace: :different,
                              public: :different,
                              collision: false

        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :same,
                              public: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :same,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :same,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :same,
                              public: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :different,
                              public: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :different,
                              public: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :different,
                              public: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without realm_id',
                              workspace: :different,
                              public: :different,
                              private: :different,
                              collision: false

        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :same,
                              realm: :same,
                              private: :same,
                              collision: true
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :same,
                              realm: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :same,
                              realm: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :same,
                              realm: :different,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :different,
                              realm: :same,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :different,
                              realm: :same,
                              private: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :different,
                              realm: :different,
                              private: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_, private_id) without public_id',
                              workspace: :different,
                              realm: :different,
                              private: :different,
                              collision: false

        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :same,
                              realm: :same,
                              public: :same,
                              collision: true
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :same,
                              realm: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :same,
                              realm: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :same,
                              realm: :different,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :different,
                              realm: :same,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :different,
                              realm: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :different,
                              realm: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id) without private_id',
                              workspace: :different,
                              realm: :different,
                              public: :different,
                              collision: false

        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :same,
                              private: :same,
                              public: :same,
                              collision: true
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :same,
                              private: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :same,
                              private: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :same,
                              private: :different,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :different,
                              private: :same,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :different,
                              private: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :different,
                              private: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :same,
                              realm: :different,
                              private: :different,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :same,
                              private: :same,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :same,
                              private: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :same,
                              private: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :same,
                              private: :different,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :different,
                              private: :same,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :different,
                              private: :same,
                              public: :different,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :different,
                              private: :different,
                              public: :same,
                              collision: false
        it_should_behave_like 'on (workspace_id, realm_id, public_id, private_id)',
                              workspace: :different,
                              realm: :different,
                              private: :different,
                              public: :different,
                              collision: false

        #
        # Cross-uniqueness validation tests
        #

        context 'across validations' do
          include_context 'two metasploit_credential_cores'

          subject {
            second_metasploit_credential_core
          }

          let(:first_public) {
            FactoryBot.create(:metasploit_credential_username)
          }

          let(:first_realm) {
            FactoryBot.create(:metasploit_credential_realm)
          }

          let(:second_private) {
            first_private
          }

          let(:second_public) {
            first_public
          }

          let(:second_realm) {
            first_realm
          }

          let(:second_workspace) {
            first_workspace
          }

          context 'with workspace with realm with public with private' do
            context 'with same workspace without realm without public with same private' do
              let(:second_public) {
                nil
              }

              let(:second_realm) {
                nil
              }

              it { is_expected.to be_valid }
            end

            context 'with same workspace without realm with same public without private' do
              let(:second_private) {
                nil
              }

              let(:second_realm) {
                nil
              }

              it { is_expected.to be_valid }
            end

            context 'with same workspace with same realm without public with same private' do
              let(:second_public) {
                nil
              }

              it { is_expected.to be_valid }
            end

            context 'with same workspace with same realm with same public without private' do
              let(:second_private) {
                nil
              }

              let(:second_realm) {
                nil
              }

              it { is_expected.to be_valid }
            end
          end

          context 'with workspace without realm without public with private' do
            let(:first_public) {
              nil
            }

            let(:first_realm) {
              nil
            }

            context 'with same workspace without realm with public without private' do
              let(:second_public) {
                FactoryBot.create(:metasploit_credential_public)
              }

              let(:second_private) {
                nil
              }

              it { is_expected.to be_valid }
            end

            context 'with same workspace without realm with public with same private' do
              let(:second_public) {
                FactoryBot.create(:metasploit_credential_public)
              }

              it { is_expected.to be_valid }
            end

            context 'with same workspace with realm without public with same private' do
              let(:second_realm) {
                FactoryBot.create(:metasploit_credential_realm)
              }

              it { is_expected.to be_valid }
            end
          end

          context 'with workspace without realm with public without private' do
            let(:first_private) {
              nil
            }

            let(:first_realm) {
              nil
            }

            context 'with workspace without realm with same public with private' do
              let(:second_private) {
                FactoryBot.create(:metasploit_credential_private)
              }

              it { is_expected.to be_valid }
            end

            context 'with workspace with realm without public with private' do
              let(:second_private) {
                FactoryBot.create(:metasploit_credential_private)
              }

              let(:second_realm) {
                FactoryBot.create(:metasploit_credential_realm)
              }

              it { is_expected.to be_valid}
            end
          end

          context 'with workspace without realm with public with private' do
            let(:first_realm) {
              nil
            }

            context 'with same workspace with realm without public with same private' do
              let(:second_public) {
                nil
              }

              let(:second_realm) {
                FactoryBot.create(:metasploit_credential_realm)
              }

              it { is_expected.to be_valid }
            end
          end

          context 'with workspace with realm without public with private' do
            let(:first_public) {
              nil
            }

            context 'with same workspace with same realm with public without private' do
              let(:second_private) {
                nil
              }

              let(:second_public) {
                FactoryBot.create(:metasploit_credential_public)
              }

              it { is_expected.to be_valid }
            end
          end
        end

      end
    end
  end


end