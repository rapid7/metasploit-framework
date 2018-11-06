require 'spec_helper'

RSpec.describe Metasploit::Credential::Origin::Service, type: :model do


  subject(:service_origin) do
    FactoryBot.build(:metasploit_credential_origin_service)
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:cores).class_name('Metasploit::Credential::Core').dependent(:destroy) }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
  end

  context 'database' do
    context 'columns' do
      it_should_behave_like 'timestamp database columns'

      it { is_expected.to have_db_column(:module_full_name).of_type(:text).with_options(null: false) }

      context 'foreign keys' do
        it { is_expected.to have_db_column(:service_id).of_type(:integer).with_options(null: false) }
      end
    end

    context 'indices' do
      it { is_expected.to have_db_index([:service_id, :module_full_name]).unique(true) }
    end
  end

  context 'factories' do
    context 'metasploit_credential_origin_service' do
      subject(:metasploit_credential_origin_service) do
        FactoryBot.build(:metasploit_credential_origin_service)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    context '#module_full_name' do
      # there is no way to test all values that match and do not match a regex, so testing by value is all that's
      # possible.
      context 'format' do
        #
        # lets
        #

        let(:module_full_name) do
          [
              module_type,
              'reference',
              'name'
          ].join(separator)
        end

        context "with '/'" do
          let(:separator) do
            '/'
          end

          context 'with auxiliary' do
            let(:module_type) do
              'auxiliary'
            end

            it 'allows value' do
              expect(service_origin).to allow_value(module_full_name).for(:module_full_name)
            end
          end

          context 'with encoder' do
            let(:module_type) do
              'encoder'
            end

            it 'allows value' do
              expect(service_origin).not_to allow_value(module_full_name).for(:module_full_name)
            end
          end

          context 'with exploit' do
            let(:module_type) do
              'exploit'
            end

            it 'allows value' do
              expect(service_origin).to allow_value(module_full_name).for(:module_full_name)
            end
          end

          context 'with nop' do
            let(:module_type) do
              'nop'
            end

            it 'allows value' do
              expect(service_origin).not_to allow_value(module_full_name).for(:module_full_name)
            end
          end

          context 'with payload' do
            let(:module_type) do
              'payload'
            end

            it 'allows value' do
              expect(service_origin).not_to allow_value(module_full_name).for(:module_full_name)
            end
          end

          context 'with post' do
            let(:module_type) do
              'post'
            end

            it 'allows value' do
              expect(service_origin).to allow_value(module_full_name).for(:module_full_name)
            end
          end
        end

        context "with '\\'" do
          let(:separator) do
            '\\'
          end

          context 'with auxiliary' do
            let(:module_type) do
              'auxiliary'
            end

            it 'does not allow value' do
              expect(service_origin).not_to allow_value(module_full_name).for(:module_full_name)
            end
          end

          context 'with exploit' do
            let(:module_type) do
              'exploit'
            end

            it 'does not allow value' do
              expect(service_origin).not_to allow_value(module_full_name).for(:module_full_name)
            end
          end
        end
      end

      context do
        # example to sample for service_id
        before(:example) do
          FactoryBot.create(:metasploit_credential_origin_service)
        end

        it { is_expected.to validate_uniqueness_of(:module_full_name).scoped_to(:service_id) }
      end
    end

    it { is_expected.to validate_presence_of :service }
  end
end
