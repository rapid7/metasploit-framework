# Test plan for unique indexes and uniqueness validators
#
#    Index        |  First Metasploit::Credential::Core  |           |           |           |  Second Metasploit::Credential::Core  |             |             |             |  Collision  |
#    -------------|--------------------------------------|-----------|-----------|-----------|---------------------------------------|-------------|-------------|-------------|-------------|
#                 |  Workspace                           |  Realm    |  Public   |  Private  |  Workspace                            |  Realm      |  Public     |  Private    |             |
#    private      |  non-nil                             |  nil      |  nil      |  non-nil  |  same                                 |  nil        |  nil        |  same       |  TRUE       |
#    private      |  non-nil                             |  nil      |  nil      |  non-nil  |  same                                 |  nil        |  nil        |  different  |  FALSE      |
#    private      |  non-nil                             |  nil      |  nil      |  non-nil  |  different                            |  nil        |  nil        |  same       |  FALSE      |
#    private      |  non-nil                             |  nil      |  nil      |  non-nil  |  different                            |  nil        |  nil        |  different  |  FALSE      |
#    public       |  non-nil                             |  nil      |  non-nil  |  nil      |  same                                 |  nil        |  same       |  nil        |  TRUE       |
#    public       |  non-nil                             |  nil      |  non-nil  |  nil      |  same                                 |  nil        |  different  |  nil        |  FALSE      |
#    public       |  non-nil                             |  nil      |  non-nil  |  nil      |  different                            |  nil        |  same       |  nil        |  FALSE      |
#    public       |  non-nil                             |  nil      |  non-nil  |  nil      |  different                            |  nil        |  different  |  nil        |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  same                                 |  nil        |  same       |  same       |  TRUE       |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  same                                 |  nil        |  same       |  different  |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  same                                 |  nil        |  different  |  same       |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  same                                 |  nil        |  different  |  different  |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  different                            |  nil        |  same       |  same       |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  different                            |  nil        |  same       |  different  |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  different                            |  nil        |  different  |  same       |  FALSE      |
#    realmless    |  non-nil                             |  nil      |  non-nil  |  non-nil  |  different                            |  nil        |  different  |  different  |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  same                                 |  same       |  nil        |  same       |  TRUE       |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  same                                 |  same       |  nil        |  different  |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  same                                 |  different  |  nil        |  same       |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  same                                 |  different  |  nil        |  different  |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  different                            |  same       |  nil        |  same       |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  different                            |  same       |  nil        |  different  |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  different                            |  different  |  nil        |  same       |  FALSE      |
#    publicless   |  non-nil                             |  non-nil  |  nil      |  non-nil  |  different                            |  different  |  nil        |  different  |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  same                                 |  same       |  same       |  nil        |  TRUE       |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  same                                 |  same       |  different  |  nil        |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  same                                 |  different  |  same       |  nil        |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  same                                 |  different  |  different  |  nil        |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  different                            |  same       |  same       |  nil        |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  different                            |  same       |  different  |  nil        |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  different                            |  different  |  same       |  nil        |  FALSE      |
#    privateless  |  non-nil                             |  non-nil  |  non-nil  |  nil      |  different                            |  different  |  different  |  nil        |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  same       |  same       |  same       |  TRUE       |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  same       |  same       |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  same       |  different  |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  same       |  different  |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  different  |  same       |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  different  |  same       |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  different  |  different  |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  same                                 |  different  |  different  |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  same       |  same       |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  same       |  same       |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  same       |  different  |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  same       |  different  |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  different  |  same       |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  different  |  same       |  different  |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  different  |  different  |  same       |  FALSE      |
#    complete     |  non-nil                             |  non-nil  |  non-nil  |  non-nil  |  different                            |  different  |  different  |  different  |  FALSE      |
#
RSpec.describe Metasploit::Credential::Core, type: :model do


  subject(:core) do
    described_class.new
  end


  #
  # Examples
  #

  it_should_behave_like 'Metasploit::Credential::CoreValidations'

  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_and_belong_to_many(:tasks).class_name('Mdm::Task') }
    it { is_expected.to have_many(:logins).class_name('Metasploit::Credential::Login').dependent(:destroy) }
    it { is_expected.to belong_to(:origin) }
    it { is_expected.to belong_to(:private).class_name('Metasploit::Credential::Private') }
    it { is_expected.to belong_to(:public).class_name('Metasploit::Credential::Public') }
    it { is_expected.to belong_to(:realm).class_name('Metasploit::Credential::Realm') }
    it { is_expected.to belong_to(:workspace).class_name('Mdm::Workspace') }
  end

  context 'database' do
    context 'columns' do
      context 'foreign keys' do
        context 'polymorphic origin' do
          it { is_expected.to have_db_column(:origin_id).of_type(:integer).with_options(null: false) }
          it { is_expected.to have_db_column(:origin_type).of_type(:string).with_options(null: false) }
        end

        it { is_expected.to have_db_column(:private_id).of_type(:integer).with_options(null: true) }
        it { is_expected.to have_db_column(:public_id).of_type(:integer).with_options(null: true) }
        it { is_expected.to have_db_column(:realm_id).of_type(:integer).with_options(null: true) }
        it { is_expected.to have_db_column(:workspace_id).of_type(:integer).with_options(null: false) }
      end

      it_should_behave_like 'timestamp database columns'
    end

    context 'indices' do
      context 'foreign keys' do

        it { is_expected.to have_db_index([:origin_type, :origin_id]) }
        it { is_expected.to have_db_index(:private_id) }
        it { is_expected.to have_db_index(:public_id) }
        it { is_expected.to have_db_index(:realm_id) }
        it { is_expected.to have_db_index(:workspace_id) }


      end
    end
  end

  context 'scopes' do

    context '.workspace_id' do
      let(:query) { described_class.workspace_id(workspace_id) }

      subject(:metasploit_credential_core) do
        FactoryBot.create(:metasploit_credential_core)
      end

      context 'when given a valid workspace id' do
        let(:workspace_id) { metasploit_credential_core.workspace_id }

        it 'returns the correct Core' do
          expect(query).to eq [metasploit_credential_core]
        end
      end

      context 'when given an invalid workspace id' do
        let(:workspace_id) { -1 }

        it 'returns an empty collection' do
          expect(query).to be_empty
        end
      end
    end

    context '.login_host_id' do
      let(:query) { described_class.login_host_id(host_id) }
      let(:login) { FactoryBot.create(:metasploit_credential_login) }
      subject(:metasploit_credential_core) { login.core }

      context 'when given a valid host id' do
        let(:host_id) { metasploit_credential_core.logins.first.service.host.id }

        it 'returns the correct Core' do
          expect(query).to eq [metasploit_credential_core]
        end
      end

      context 'when given an invalid host id' do
        let(:host_id) { -1 }

        it 'returns an empty collection' do
          expect(query).to be_empty
        end
      end
    end

    context '.origin_service_host_id' do
      let(:query) { described_class.origin_service_host_id(host_id) }
      let(:workspace) { FactoryBot.create(:mdm_workspace) }

      subject(:metasploit_credential_core) do
        FactoryBot.create(:metasploit_credential_core_service)
      end

      context 'when given a valid host id' do
        let(:host_id) { metasploit_credential_core.origin.service.host.id }

        it 'returns the correct Core' do
          expect(query).to eq [metasploit_credential_core]
        end
      end

      context 'when given an invalid host id' do
        let(:host_id) { -1 }

        it 'returns an empty collection' do
          expect(query).to be_empty
        end
      end
    end

    context '.origin_session_host_id' do
      let(:query) { described_class.origin_session_host_id(host_id) }

      subject(:metasploit_credential_core) do
        FactoryBot.create(:metasploit_credential_core_session)
      end

      context 'when given a valid host id' do
        let(:host_id) { metasploit_credential_core.origin.session.host.id }

        it 'returns the correct Core' do
          expect(query).to eq [metasploit_credential_core]
        end
      end

      context 'when given an invalid host id' do
        let(:host_id) { -1 }

        it 'returns an empty collection' do
          expect(query).to be_empty
        end
      end
    end

    context '.originating_host_id' do
      let(:query) { described_class.originating_host_id(host_id) }

      # Create a couple Cores that are related to the host via session
      let(:metasploit_credential_core_sessions) do
        FactoryBot.create_list(:metasploit_credential_core_session, 2)
      end

      # Create a couple Cores that are related to the host via service
      let(:metasploit_credential_core_services) do
        FactoryBot.create_list(:metasploit_credential_core_service, 2)
      end

      # Create an unrelated Core
      let(:unrelated_metasploit_credential_core) do
        FactoryBot.create(:metasploit_credential_core_service)
      end

      before do
        # make sure they are all related to the same host
        # ideally this would be done in the factory, but one look at the factories and i am punting.
        init_host_id = metasploit_credential_core_services.first.origin.service.host.id

        metasploit_credential_core_services.each do |core|
          core.origin.service.host_id = init_host_id
          core.origin.service.save
        end

        metasploit_credential_core_sessions.each do |core|
          core.origin.session.host_id = init_host_id
          core.origin.session.save
        end

        # Make sure the unrelated core is actually created
        unrelated_metasploit_credential_core
      end

      context 'when given a valid host id' do
        let(:host_id) { metasploit_credential_core_sessions.first.origin.session.host.id }

        it 'returns an ActiveRecord::Relation' do
          expect(query).to be_an ActiveRecord::Relation
        end

        it 'returns the correct Cores' do
          expect(query).to match_array metasploit_credential_core_sessions + metasploit_credential_core_services
        end
      end

      context 'when given an invalid host id' do
        let(:host_id) { -1 }

        it 'returns an ActiveRecord::Relation' do
          expect(query).to be_an ActiveRecord::Relation
        end

        it 'returns an empty collection' do
          expect(query).to be_empty
        end
      end
    end

  end

  context 'search' do
    let(:base_class) {
      described_class
    }

    context 'associations' do
      it_should_behave_like 'search_association', :logins
      it_should_behave_like 'search_association', :private
      it_should_behave_like 'search_association', :public
      it_should_behave_like 'search_association', :realm
    end
  end

  context 'factories' do
    context 'metasploit_credential_core' do
      subject(:metasploit_credential_core) do
        FactoryBot.build(:metasploit_credential_core)
      end

      let(:origin) do
        metasploit_credential_core.origin
      end

      it { is_expected.to be_valid }

      context 'with origin_factory' do
        subject(:metasploit_credential_core) do
          FactoryBot.build(
              :metasploit_credential_core,
              origin_factory: origin_factory
          )
        end

        context ':metasploit_credential_origin_import' do
          let(:origin_factory) do
            :metasploit_credential_origin_import
          end

          it { is_expected.to be_valid }
        end

        context ':metasploit_credential_origin_manual' do
          let(:origin_factory) do
            :metasploit_credential_origin_manual
          end

          it { is_expected.to be_valid }

          context '#origin' do
            subject(:origin) do
              metasploit_credential_core.origin
            end

            it { is_expected.to be_a Metasploit::Credential::Origin::Manual }
          end

          context '#workspace' do
            subject(:workspace) do
              metasploit_credential_core.workspace
            end

            it { is_expected.not_to be_nil }
          end
        end

        context ':metasploit_credential_origin_service' do
          let(:origin_factory) do
            :metasploit_credential_origin_service
          end

          it { is_expected.to be_valid }

          context '#workspace' do
            subject(:workspace) do
              metasploit_credential_core.workspace
            end

            it 'is origin.service.host.workspace' do
              expect(workspace).not_to be_nil
              expect(workspace).to eq(origin.service.host.workspace)
            end
          end
        end

        context ':metasploit_credential_origin_session' do
          let(:origin_factory) do
            :metasploit_credential_origin_session
          end

          it { is_expected.to be_valid }

          context '#workspace' do
            subject(:workspace) do
              metasploit_credential_core.workspace
            end

            it 'is origin.session.host.workspace' do
              expect(workspace).not_to be_nil
              expect(workspace).to eq(origin.session.host.workspace)
            end
          end
        end
      end
    end

    context 'metasploit_credential_core_import' do
      subject(:metasploit_credential_core_import) do
        FactoryBot.build(:metasploit_credential_core_import)
      end

      it { is_expected.to be_valid }
    end

    context 'metasploit_credential_core_manual' do
      subject(:metasploit_credential_core_manual) do
        FactoryBot.build(:metasploit_credential_core_manual)
      end

      it { is_expected.to be_valid }

      context '#workspace' do
        subject(:workspace) do
          metasploit_credential_core_manual.workspace
        end

        it { is_expected.not_to be_nil }
      end
    end

    context 'metasploit_credential_core_service' do
      subject(:metasploit_credential_core_service) do
        FactoryBot.build(:metasploit_credential_core_service)
      end

      it { is_expected.to be_valid }

      context '#workspace' do
        subject(:workspace) do
          metasploit_credential_core_service.workspace
        end

        let(:origin) do
          metasploit_credential_core_service.origin
        end

        it 'is origin.service.host.workspace' do
          expect(workspace).not_to be_nil
          expect(workspace).to eq(origin.service.host.workspace)
        end
      end
    end

    context 'metasploit_credential_core_session' do
      subject(:metasploit_credential_core_session) do
        FactoryBot.build(:metasploit_credential_core_session)
      end

      it { is_expected.to be_valid }

      context '#workspace' do
        subject(:workspace) do
          metasploit_credential_core_session.workspace
        end

        let(:origin) do
          metasploit_credential_core_session.origin
        end

        it 'is origin.session.host.workspace' do
          expect(workspace).not_to be_nil
          expect(workspace).to eq(origin.session.host.workspace)
        end
      end
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of :origin }


    context '#consistent_workspaces' do
      subject(:workspace_errors) do
        core.errors[:workspace]
      end

      #
      # lets
      #

      let(:core) do
        FactoryBot.build(
            :metasploit_credential_core,
            origin: origin,
            workspace: workspace
        )
      end

      let(:workspace) do
        FactoryBot.create(:mdm_workspace)
      end

      #
      # Callbacks
      #

      before(:example) do
        core.valid?
      end

      context '#origin' do
        context 'with Metasploit::Credential::Origin::Manual' do
          let(:error) do
            I18n.translate!('activerecord.errors.models.metasploit/credential/core.attributes.workspace.origin_user_workspaces')
          end

          let(:origin) do
            FactoryBot.build(
                :metasploit_credential_origin_manual,
                user: user
            )
          end

          context 'with Metasploit::Credential::Origin::Manual#user' do
            let(:user) do
              FactoryBot.build(
                  :mdm_user,
                  admin: admin
              )
            end

            context 'with Mdm::User#admin' do
              let(:admin) do
                true
              end

              it { is_expected.not_to include error }
            end

            context 'without Mdm::User#admin' do
              let(:admin) do
                false
              end

              context 'with #workspace in Mdm::User#workspaces' do
                let(:user) do
                  super().tap { |user|
                    user.workspaces << workspace
                  }
                end

                context 'with persisted' do
                  let(:user) do
                    super().tap { |user|
                      user.save!
                    }
                  end

                  it { is_expected.not_to include error }
                end

                context 'without persisted' do
                  it { is_expected.not_to include error }
                end
              end

              context 'without #workspace in Mdm::User#workspaces' do
                it { is_expected.to include error }
              end
            end
          end

          context 'without Metasploit::Credential::Origin::Manual#user' do
            let(:user) do
              nil
            end

            it { is_expected.to include error }
          end
        end

        context 'with Metasploit::Credential::Origin::Service' do
          let(:error) do
            I18n.translate!('activerecord.errors.models.metasploit/credential/core.attributes.workspace.origin_service_host_workspace')
          end

          let(:origin) do
            FactoryBot.build(
                :metasploit_credential_origin_service,
                service: service
            )
          end

          context 'with Metasploit::Credential::Origin::Service#service' do
            let(:service) do
              FactoryBot.build(
                  :mdm_service,
                  host: host
              )
            end

            context 'with Mdm::Service#host' do
              let(:host) do
                FactoryBot.build(
                    :mdm_host,
                    workspace: host_workspace
                )
              end

              context 'same as #workspace' do
                let(:host_workspace) do
                  workspace
                end

                it { is_expected.not_to include error }
              end

              context 'different than #workspace' do
                let(:host_workspace) do
                  FactoryBot.create(:mdm_workspace)
                end

                it { is_expected.to include error }
              end
            end

            context 'without Mdm::Service#host' do
              let(:host) do
                nil
              end

              it { is_expected.to include error }
            end
          end

          context 'without Metasploit::Credential::Origin::Service#service' do
            let(:service) do
              nil
            end

            it { is_expected.to include error }
          end
        end

        context 'with Metasploit::Credential::Origin::Session' do
          let(:error) do
            I18n.translate!('activerecord.errors.models.metasploit/credential/core.attributes.workspace.origin_session_host_workspace')
          end

          let(:origin) do
            FactoryBot.build(
                :metasploit_credential_origin_session,
                session: session
            )
          end

          context 'with Metasploit::Credential::Origin::Session#session' do
            let(:session) do
              FactoryBot.build(
                  :mdm_session,
                  host: host
              )
            end

            context 'with Mdm::Session#host' do
              let(:host) do
                FactoryBot.build(
                    :mdm_host,
                    workspace: host_workspace
                )
              end

              context 'with Mdm::Host#workspace' do
                context 'same as #workspace' do
                  let(:host_workspace) do
                    workspace
                  end

                  it { is_expected.not_to include error }
                end

                context 'different than #workspace' do
                  let(:host_workspace) do
                    FactoryBot.create(:mdm_workspace)
                  end

                  it { is_expected.to include error }
                end
              end

              context 'without Mdm::Host#workspace' do
                let(:host_workspace) do
                  nil
                end

                it { is_expected.to include error }
              end
            end

            context 'without Mdm::Session#host' do
              let(:host) do
                nil
              end

              it { is_expected.to include error }
            end
          end

          context 'without Metasploit::Credential::Origin::Session#session' do
            let(:session) do
              nil
            end

            it { is_expected.to include error }
          end
        end
      end
    end

    context '#minimum_presence' do
      subject(:base_errors) do
        core.errors[:base]
      end

      #
      # lets
      #

      let(:core) do
        FactoryBot.build(
            :metasploit_credential_core,
            private: private,
            public: public,
            realm: realm
        )
      end

      let(:error) do
        I18n.translate!('activerecord.errors.models.metasploit/credential/core.attributes.base.minimum_presence')
      end

      #
      # Callbacks
      #

      before(:example) do
        core.valid?
      end

      context 'with #private' do
        let(:private) do
          FactoryBot.build(private_factory)
        end

        let(:private_factory) do
          FactoryBot.generate :metasploit_credential_core_private_factory
        end

        context 'with #public' do
          let(:public) do
            FactoryBot.build(:metasploit_credential_public)
          end

          context 'with #realm' do
            let(:realm) do
              FactoryBot.build(realm_factory)
            end

            let(:realm_factory) do
              FactoryBot.generate :metasploit_credential_core_realm_factory
            end

            it { is_expected.not_to include(error) }
          end

          context 'without #realm' do
            let(:realm) do
              nil
            end

            it { is_expected.not_to include(error) }
          end
        end

        context 'without #public' do
          let(:public) do
            nil
          end

          context 'with #realm' do
            let(:realm) do
              FactoryBot.build(realm_factory)
            end

            let(:realm_factory) do
              FactoryBot.generate :metasploit_credential_core_realm_factory
            end

            it { is_expected.not_to include(error) }
          end

          context 'without #realm' do
            let(:realm) do
              nil
            end

            it { is_expected.not_to include(error) }
          end
        end
      end

      context 'without #private' do
        let(:private) do
          nil
        end

        context 'with #public' do
          let(:public) do
            FactoryBot.build(:metasploit_credential_public)
          end

          context 'with #realm' do
            let(:realm) do
              FactoryBot.build(realm_factory)
            end

            let(:realm_factory) do
              FactoryBot.generate :metasploit_credential_core_realm_factory
            end

            it { is_expected.not_to include(error) }
          end

          context 'without #realm' do
            let(:realm) do
              nil
            end

            it { is_expected.not_to include(error) }
          end
        end

        context 'without #public' do
          let(:public) do
            nil
          end

          context 'with #realm' do
            let(:realm) do
              FactoryBot.build(realm_factory)
            end

            let(:realm_factory) do
              FactoryBot.generate :metasploit_credential_core_realm_factory
            end

            it { is_expected.not_to include(error) }
          end

        end
      end
    end

    context "#public_for_ssh_key" do
      let(:error) do
        I18n.translate!('activerecord.errors.models.metasploit/credential/core.attributes.base.public_for_ssh_key')
      end

      subject(:core) do
        FactoryBot.build(
            :metasploit_credential_core,
            private: FactoryBot.build(:metasploit_credential_ssh_key),
            public: FactoryBot.build(:metasploit_credential_public)
        )
      end

      it { is_expected.to be_valid }

      context "when the Public is missing" do
        before(:example) do
          core.public = nil
        end

        it 'should not be valid if Private is an SSHKey and Public is missing' do
          expect(core).not_to be_valid
        end

        it 'should show the proper error' do
          core.valid?
          expect(core.errors[:base]).to include(error)
        end
      end

    end

  end

end
