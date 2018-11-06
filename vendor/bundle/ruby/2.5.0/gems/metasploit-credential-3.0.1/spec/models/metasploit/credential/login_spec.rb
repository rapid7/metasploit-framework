RSpec.describe Metasploit::Credential::Login, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:core).class_name('Metasploit::Credential::Core') }
    it { is_expected.to have_one(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service')}
  end

  context 'callbacks' do
    context 'before_valiation' do
      context '#blank_to_nil' do


        let(:login) do
          FactoryBot.build(
              :metasploit_credential_login,
              access_level: written_access_level
          )
        end

        #
        # Callbacks
        #

        before(:example) do
          login.valid?
        end

        context '#access_level' do
          subject(:access_level) do
            login.access_level
          end

          context 'with blank' do
            let(:written_access_level) do
              ''
            end

            it { is_expected.to be_nil }
          end

          context 'with nil' do
            let(:written_access_level) do
              nil
            end

            it { is_expected.to be_nil }
          end

          context 'with present' do
            let(:written_access_level) do
              'admin'
            end

            it 'is not changed' do
              expect(access_level).to eq(written_access_level)
            end
          end
        end
      end
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:access_level).of_type(:string).with_options(null: true) }
      it { is_expected.to have_db_column(:last_attempted_at).of_type(:datetime).with_options(null: true) }
      it { is_expected.to have_db_column(:status).of_type(:string).with_options(null: false) }

      it_should_behave_like 'timestamp database columns'

      context 'foreign keys' do
        it { is_expected.to have_db_column(:core_id).of_type(:integer).with_options(null: false) }
        it { is_expected.to have_db_column(:service_id).of_type(:integer).with_options(null: false) }
      end
    end

    context 'indices' do
      it { is_expected.to have_db_index([:core_id, :service_id]).unique(true) }
      it { is_expected.to have_db_index([:service_id, :core_id]).unique(true) }
    end
  end

  context 'factories' do


    context 'metasploit_credential_login' do
      subject(:metasploit_credential_login) do
        FactoryBot.build(:metasploit_credential_login)
      end

      it { is_expected.to be_valid }

      context '#status' do
        subject(:metasploit_credential_login) do
          FactoryBot.build(
              :metasploit_credential_login,
              status: status
          )
        end

        context 'with Metasploit::Model::Login::Status::DENIED_ACCESS' do
          let(:status) do
            Metasploit::Model::Login::Status::DENIED_ACCESS
          end

          it { is_expected.to be_valid }
        end

        context 'with Metasploit::Model::Login::Status::DISABLED' do
          let(:status) do
            Metasploit::Model::Login::Status::DISABLED
          end

          it { is_expected.to be_valid }
        end

        context 'with Metasploit::Model::Login::Status::LOCKED_OUT' do
          let(:status) do
            Metasploit::Model::Login::Status::LOCKED_OUT
          end

          it { is_expected.to be_valid }
        end

        context 'with Metasploit::Model::Login::Status::SUCCESSFUL' do
          let(:status) do
            Metasploit::Model::Login::Status::SUCCESSFUL
          end

          it { is_expected.to be_valid }
        end

        context 'with Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
          let(:status) do
            Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          end

          it { is_expected.to be_valid }
        end

        context 'with Metasploit::Model::Login::Status::UNTRIED' do
          let(:status) do
            Metasploit::Model::Login::Status::UNTRIED
          end

          it { is_expected.to be_valid }
        end
      end
    end
  end

  context 'search' do
    let(:base_class) {
      described_class
    }

    context 'associations' do
      it_should_behave_like 'search_association',
                            :host
      it_should_behave_like 'search_association',
                            :service
    end

    context 'attributes' do
      it_should_behave_like 'search_attribute',
                            :access_level,
                            type: :string

      it_should_behave_like 'search_attribute',
                            :status,
                            type: {
                                set: :string
                            }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of :core }

    context 'with existent Metasploit::Credential::Login' do


      before(:example) do
        # validate_uniqueness_of will use Metasploit::Credential::Login#service_id and not trigger service_id non-null
        # constraint.
        FactoryBot.create(
            :metasploit_credential_login
        )
      end

      it { is_expected.to validate_uniqueness_of(:core_id).scoped_to(:service_id) }
    end

    it { is_expected.to validate_presence_of :service }
    it { is_expected.to validate_inclusion_of(:status).in_array(Metasploit::Model::Login::Status::ALL) }

    context '#consistent_last_attempted_at' do


      subject(:last_attempted_at_errors) do
        login.errors[:last_attempted_at]
      end

      #
      # lets
      #

      let(:login) do
        FactoryBot.build(
            :metasploit_credential_login,
            last_attempted_at: last_attempted_at,
            status: status
        )
      end

      #
      # Callbacks
      #

      before(:example) do
        login.valid?
      end

      context '#status' do
        context 'with Metasploit::Model::Login::Status::UNTRIED' do
          let(:error) do
            I18n.translate!('activerecord.errors.models.metasploit/credential/login.attributes.last_attempted_at.untried')
          end

          let(:status) do
            Metasploit::Model::Login::Status::UNTRIED
          end

          context 'with #last_attempted' do
            let(:last_attempted_at) do
              DateTime.now.utc
            end

            it { is_expected.to include(error) }
          end

          context 'without #last_attempted' do
            let(:last_attempted_at) do
              nil
            end

            it { is_expected.not_to include(error) }
          end
        end

        context 'without Metasploit::Model::Login::Status::UNTRIED' do
          let(:error) do
            I18n.translate!('activerecord.errors.models.metasploit/credential/login.attributes.last_attempted_at.tried')
          end

          let(:status) do
            statuses.sample
          end

          let(:statuses) do
            Metasploit::Model::Login::Status::ALL - [Metasploit::Model::Login::Status::UNTRIED]
          end

          context 'with #last_attempted' do
            let(:last_attempted_at) do
              DateTime.now.utc
            end

            it { is_expected.not_to include(error) }
          end

          context 'without #last_attempted' do
            let(:last_attempted_at) do
              nil
            end

            it { is_expected.to include(error) }
          end
        end
      end
    end

    context '#consistent_workspaces' do


      subject(:workspace_errors) do
        login.errors[:base]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!('activerecord.errors.models.metasploit/credential/login.attributes.base.inconsistent_workspaces')
      end

      let(:login) do
        FactoryBot.build(
            :metasploit_credential_login,
            core: core,
            service: service
        )
      end

      #
      # Callbacks
      #

      before(:example) do
        login.valid?
      end

      context 'with #core' do
        let(:core) do
          FactoryBot.build(:metasploit_credential_core)
        end

        context 'with Metasploit::Credential::Core#workspace' do
          context 'with #service' do
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
                    workspace: workspace
                )
              end

              context 'with Mdm::Host#workspace' do
                context 'same as #workspace' do
                  let(:workspace) do
                    core.workspace
                  end

                  it { is_expected.not_to include(error) }
                end

                context 'different than #workspace' do
                  let(:workspace) do
                    FactoryBot.build(:mdm_workspace)
                  end

                  it { is_expected.to include(error) }
                end
              end

              context 'without Mdm::Host#workspace' do
                let(:workspace) do
                  nil
                end

                it { is_expected.to include(error) }
              end
            end

            context 'without Mdm::Service#host' do
              let(:host) do
                nil
              end

              it { is_expected.to include(error) }
            end
          end

          context 'without #service' do
            let(:service) do
              nil
            end

            it { is_expected.to include(error) }
          end
        end

        context 'without Metasploit::Credential::Core#workspace' do
          let(:core) do
            super().tap { |core|
              core.workspace = nil
            }
          end

          context 'with #service' do
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
                    workspace: workspace
                )
              end

              context 'with Mdm::Host#workspace' do
                let(:workspace) do
                  FactoryBot.build(:mdm_workspace)
                end

                it { is_expected.to include(error) }
              end

              context 'without Mdm::Host#workspace' do
                let(:workspace) do
                  nil
                end

                it { is_expected.not_to include(error) }
              end
            end

            context 'without Mdm::Service#host' do
              let(:host) do
                nil
              end

              it { is_expected.not_to include(error) }
            end
          end

          context 'without #service' do
            let(:service) do
              nil
            end

            it { is_expected.not_to include(error) }
          end
        end
      end

      context 'without #core' do
        let(:core) do
          nil
        end

        context 'with #service' do
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
                  workspace: workspace
              )
            end

            context 'with Mdm::Host#workspace' do
              let(:workspace) do
                FactoryBot.build(:mdm_workspace)
              end

              it { is_expected.to include(error) }
            end

            context 'without Mdm::Host#workspace' do
              let(:workspace) do
                nil
              end

              it { is_expected.not_to include(error) }
            end
          end

          context 'without Mdm::Service#host' do
            let(:host) do
              nil
            end

            it { is_expected.not_to include(error) }
          end
        end

        context 'without #service' do
          let(:service) do
            nil
          end

          it { is_expected.not_to include(error) }
        end
      end
    end
  end

  context "scopes" do


    context "::in_workspace_with_hosts_and_services" do
      let(:service){ FactoryBot.create :mdm_service }
      let(:origin){ FactoryBot.create :metasploit_credential_origin_service, service: service}
      let(:core){ FactoryBot.create :metasploit_credential_core, workspace: service.host.workspace, origin: origin}

      subject(:login){ FactoryBot.create :metasploit_credential_login, core: core}

      it 'should find the right objects' do
        expect(Metasploit::Credential::Login.in_workspace_including_hosts_and_services(service.host.workspace)).to include(login)
      end
    end
  end
end
