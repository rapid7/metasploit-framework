RSpec.describe Metasploit::Credential::Private, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'database' do
    context 'columns' do
      it_should_behave_like 'single table inheritance database columns'
      it_should_behave_like 'timestamp database columns'

      it { is_expected.to have_db_column(:data).of_type(:text).with_options(null: false) }
    end

    context 'indices' do
      it { is_expected.to have_db_index([:type, :data]).unique(true) }
    end
  end

  context 'factories' do
    context 'metasploit_credential_private' do
      subject(:metasploit_credential_private) do
        FactoryBot.build(:metasploit_credential_private)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    context 'data' do
      it { is_expected.to validate_non_nilness_of :data }

      # `it { is_expected.to validate_uniqueness_of(:data).scoped_to(:type) }` tries to use a NULL type, which isn't allowed, so
      # have to perform validation check manually
      context 'validates uniqueness of #data scoped to #type' do
        subject(:data_errors) do
          new_private.errors[:data]
        end

        #
        # lets
        #

        let(:error) do
          I18n.translate!(:'errors.messages.taken')
        end

        let(:new_private) do
          FactoryBot.build(
              :metasploit_credential_private,
              data: data,
              type: type
          )
        end

        #
        # let!s
        #

        let!(:existent_private) do
          FactoryBot.create(
              :metasploit_credential_private
          )
        end

        #
        # Callbacks
        #

        before(:example) do
          new_private.valid?
        end

        context 'with same #data' do
          let(:data) do
            existent_private.data
          end

          context 'with same #type' do
            let(:type) do
              existent_private.type
            end

            it { is_expected.to include(error) }
          end

          context 'without same #type' do
            let(:type) do
              FactoryBot.generate :metasploit_credential_private_type
            end

            it { is_expected.not_to include(error) }
          end
        end

        context 'without same #data' do
          let(:data) do
            FactoryBot.generate :metasploit_credential_private_data
          end

          context 'with same #type' do
            let(:type) do
              existent_private.type
            end

            it { is_expected.not_to include(error) }
          end

          context 'without same #type' do
            let(:type) do
              FactoryBot.generate :metasploit_credential_private_type
            end

            it { is_expected.not_to include(error) }
          end
        end
      end
    end
  end

  context 'search' do
    let(:base_class) {
      described_class
    }

    context 'attributes' do
      it_should_behave_like 'search_attribute',
                            :type,
                            type: :string

      it_should_behave_like 'search_with',
                            Metasploit::Credential::Search::Operator::Type,
                            name: :type,
                            class_names: %w{
                              Metasploit::Credential::NonreplayableHash
                              Metasploit::Credential::NTLMHash
                              Metasploit::Credential::Password
                              Metasploit::Credential::SSHKey
                            }
    end
  end

end
