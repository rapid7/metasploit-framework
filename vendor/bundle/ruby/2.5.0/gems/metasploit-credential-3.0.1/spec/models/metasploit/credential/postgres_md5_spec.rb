RSpec.describe Metasploit::Credential::PostgresMD5, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  it { is_expected.to be_a Metasploit::Credential::ReplayableHash }

  context 'CONSTANTS' do
    context 'DATA_REGEXP' do
      subject(:data_regexp) do
        described_class::DATA_REGEXP
      end

      it 'is valid if the string is md5 and 32 hex chars' do
        hash = "md5#{SecureRandom.hex(16)}"
        expect(data_regexp).to match(hash)
      end

      it 'is not valid if it does not start with md5' do
        expect(data_regexp).not_to match(SecureRandom.hex(16))
      end

      it 'is not valid for an invalid length' do
        expect(data_regexp).not_to match(SecureRandom.hex(6))
      end

      it 'is not valid if it is not hex chars after the md5 tag' do
        bogus = "md5#{SecureRandom.hex(15)}jk"
        expect(data_regexp).not_to match(bogus)
      end

    end
  end

  context 'callbacks' do
    context 'before_validation' do
      context '#data' do
        subject(:data) do
          postgres_md5.data
        end

        let(:postgres_md5) do
          FactoryBot.build(
            :metasploit_credential_postgres_md5,
            data: given_data
          )
        end

        before(:example) do
          postgres_md5.valid?
        end

        context 'with nil' do
          let(:given_data) do
            nil
          end

          it { is_expected.to be_nil }
        end

        context 'with upper case characters' do
          let(:given_data) do
            'ABCDEF1234567890'
          end

          it 'makes them lower case' do
            expect(data).to eq(given_data.downcase)
          end
        end

        context 'with all lower case characters' do
          let(:given_data) do
            'abcdef1234567890'
          end

          it 'does not change the case' do
            expect(data).to eq(given_data)
          end
        end
      end
    end
  end

  context 'factories' do
    context 'metasploit_credential_ntlm_hash' do
      subject(:metasploit_credential_postgres_md5) do
        FactoryBot.build(:metasploit_credential_postgres_md5)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    context '#data_format' do
      subject(:data_errors) do
        postgres_md5.errors[:data]
      end

      let(:data) { "md5#{SecureRandom.hex(16)}" }

      let(:postgres_md5) do
        FactoryBot.build(
          :metasploit_credential_postgres_md5,
          data: data
        )
      end

      context 'with a valid postgres md5 hash' do
        it 'should be valid' do
          expect(postgres_md5).to be_valid
        end
      end

      context 'with an invalid postgres md5 hash' do
        let(:data) { "invalidstring" }
        it 'should not be valid' do
          expect(postgres_md5).to_not be_valid
        end
      end
    end
  end

end
