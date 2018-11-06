RSpec.describe Metasploit::Credential::Realm, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:key).of_type(:string).with_options(null: false) }
      it { is_expected.to have_db_column(:value).of_type(:string).with_options(null: false) }

      it_should_behave_like 'timestamp database columns'
    end

    context 'indices' do
      it { is_expected.to have_db_index([:key, :value]).unique(true) }
    end
  end

  context 'factories' do
    context 'metasploit_credential_active_directory_domain' do
      subject(:metasploit_credential_active_directory_domain) do
        FactoryBot.build(:metasploit_credential_active_directory_domain)
      end

      it { is_expected.to be_valid }

      context '#key' do
        subject(:key) {
          metasploit_credential_active_directory_domain.key
        }

        it 'is Metasploit::Credential::Realm::Key::ACTIVE_DIRECTORY_DOMAIN' do
          expect(key).to eq(Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN)
        end
      end
    end

    context 'metasplit_credential_oracle_system_identifier' do
      subject(:metasploit_credential_oracle_system_identifier) do
        FactoryBot.build(:metasploit_credential_oracle_system_identifier)
      end

      it { is_expected.to be_valid }

      context '#key' do
        subject(:key) {
          metasploit_credential_oracle_system_identifier.key
        }

        it 'is Metasploit::Credential::Realm::Key::ORACLE_SYSTEM_IDENTIFIER' do
          expect(key).to eq(Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER)
        end
      end
    end

    context 'metasploit_credential_postgresql_database' do
      subject(:metasploit_credential_postgresql_database) do
        FactoryBot.build(:metasploit_credential_postgresql_database)
      end

      it { is_expected.to be_valid }

      context '#key' do
        subject(:key) {
          metasploit_credential_postgresql_database.key
        }

        it 'is Metasploit::Credential::Realm::Key::POSTGRESQL_DATABASE' do
          expect(key).to eq(Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE)
        end
      end
    end

    context 'metasploit_credential_realm' do
      subject(:metasploit_credential_realm) do
        FactoryBot.build(:metasploit_credential_realm)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'search' do
    context 'attributes' do
      let(:base_class) {
        described_class
      }

      it_should_behave_like 'search_attribute',
                            :key,
                            type: {
                                set: :string
                            }

      it_should_behave_like 'search_attribute',
                            :value,
                            type: :string
    end
  end

  context 'validations' do
    context 'on #key' do
      it { is_expected.to validate_inclusion_of(:key).in_array(Metasploit::Model::Realm::Key::ALL) }
      it { is_expected.to validate_presence_of :key }
    end

    context 'on #value' do
      it { is_expected.to validate_presence_of :value }

      # key cannot be NULL so `validate_uniqueness_of(:value).scoped_to(:key)` does not work because it tries a NULL
      # key
      context 'validates uniqueness of #value scoped to #key' do
        subject(:value_errors) do
          new_realm.errors[:value]
        end

        #
        # lets
        #

        let(:error) do
          I18n.translate!('errors.messages.taken')
        end

        let(:new_realm) do
          FactoryBot.build(
              :metasploit_credential_realm,
              key: key,
              value: value
          )
        end

        #
        # let!s
        #

        let!(:existent_realm) do
          FactoryBot.create(
              :metasploit_credential_realm
          )
        end

        #
        # Callback
        #

        before(:example) do
          new_realm.valid?
        end

        context 'with same #key' do
          let(:key) do
            existent_realm.key
          end

          context 'with same #value' do
            let(:value) do
              existent_realm.value
            end

            it { is_expected.to include(error) }
          end

          context 'without same #value' do
            let(:value) do
              FactoryBot.generate :metasploit_credential_realm_value
            end

            it { is_expected.not_to include(error) }
          end
        end

        context 'without same #key' do
          let(:key) do
            FactoryBot.generate :metasploit_credential_realm_key
          end

          context 'with same #value' do
            let(:value) do
              existent_realm.value
            end

            it { is_expected.not_to include(error) }
          end

          context 'without same #value' do
            let(:value) do
              FactoryBot.generate :metasploit_credential_realm_value
            end

            it { is_expected.not_to include(error) }
          end
        end
      end
    end
  end
end
