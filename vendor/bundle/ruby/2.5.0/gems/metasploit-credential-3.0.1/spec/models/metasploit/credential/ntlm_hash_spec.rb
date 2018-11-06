RSpec.describe Metasploit::Credential::NTLMHash, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  it { is_expected.to be_a Metasploit::Credential::ReplayableHash }

  context 'CONSTANTS' do
    context 'DATA_REGEXP' do
      subject(:data_regexp) do
        described_class::DATA_REGEXP
      end

      let(:pattern) do
        data_regexp.to_s
      end

      it 'matches entire string' do
        lan_manager_hex_digest = SecureRandom.hex(16)
        nt_lan_manager_hex_digest = SecureRandom.hex(16)
        embedded_data = "#{lan_manager_hex_digest}:#{nt_lan_manager_hex_digest}"

        expect(data_regexp).not_to match("before\n#{embedded_data}\nafter")
        expect(data_regexp).to match(embedded_data)
      end

      it 'includes LAN_MANAGER_HEX_DIGEST_REGEXP' do
        expect(pattern).to include(described_class::LAN_MANAGER_HEX_DIGEST_REGEXP.to_s)
      end

      it 'includes NT_LAN_MANAGER_HEX_DIGEST_REGEXP' do
        expect(pattern).to include(described_class::NT_LAN_MANAGER_HEX_DIGEST_REGEXP.to_s)
      end
    end

    context 'LAN_MANAGER_MAX_CHARACTERS' do
      subject(:lan_manager_max_characters) do
        described_class::LAN_MANAGER_MAX_CHARACTERS
      end

      it { is_expected.to eq 14 }
    end

    context 'LAN_MANAGER_HEX_DIGEST_REGEXP' do
      subject(:lan_manager_hex_digest_regexp) do
        described_class::LAN_MANAGER_HEX_DIGEST_REGEXP
      end

      let(:hex_digest) do
        SecureRandom.hex(16)
      end

      it 'does not match entire string so that it can be used in DATA_REGEXP' do
        expect(lan_manager_hex_digest_regexp).to match("before#{hex_digest}after")
      end

      it 'matches a 32 character hexadecimal string' do
        expect(lan_manager_hex_digest_regexp).to match(hex_digest)
      end
    end

    context 'NT_LAN_MANAGER_HEX_DIGEST_REGEXP' do
      subject(:nt_lan_manager_hex_digest_regexp) do
        described_class::NT_LAN_MANAGER_HEX_DIGEST_REGEXP
      end

      let(:hex_digest) do
        SecureRandom.hex(16)
      end

      it 'does not match entire string so that it can be used in DATA_REGEXP' do
        expect(nt_lan_manager_hex_digest_regexp).to match("before#{hex_digest}after")
      end

      it 'matches a 32 character hexadecimal string' do
        expect(nt_lan_manager_hex_digest_regexp).to match(hex_digest)
      end
    end
  end

  context 'callbacks' do
    context 'before_validation' do
      context '#data' do
        subject(:data) do
          ntlm_hash.data
        end

        let(:ntlm_hash) do
          FactoryBot.build(
              :metasploit_credential_ntlm_hash,
              data: given_data
          )
        end

        before(:example) do
          ntlm_hash.valid?
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
      subject(:metasploit_credential_ntlm_hash) do
        FactoryBot.build(:metasploit_credential_ntlm_hash)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    context '#data_format' do
      subject(:data_errors) do
        ntlm_hash.errors[:data]
      end

      #
      # lets
      #

      let(:data) do
        "#{lan_manager_hex_digest}:#{nt_lan_manager_hex_digest}"
      end

      let(:error) do
        I18n.translate!(:'activerecord.errors.models.metasploit/credential/ntlm_hash.attributes.data.format')
      end

      let(:lan_manager_hex_digest) do
        described_class.lan_manager_hex_digest_from_password_data(password_data)
      end

      let(:nt_lan_manager_hex_digest) do
        described_class.nt_lan_manager_hex_digest_from_password_data(password_data)
      end

      let(:ntlm_hash) do
        FactoryBot.build(
            :metasploit_credential_ntlm_hash,
            data: data
        )
      end

      let(:password_data) do
        FactoryBot.generate :metasploit_credential_password_data
      end

      #
      # Callbacks
      #

      before(:example) do
        ntlm_hash.valid?
      end

      context 'with <LAN Manager hex digest>:<NT LAN Manager hex digest>' do
        it { is_expected.not_to include(error) }
      end

      context "without ':'" do
        let(:data) do
          super().gsub(':', '')
        end

        it { is_expected.to include(error) }
      end

      context 'without LAN Manager hex_digest' do
        let(:data) do
          ":#{nt_lan_manager_hex_digest}"
        end

        it { is_expected.to include(error) }
      end

      context 'with incorrect hash length(s)' do
        let(:data) do
          "123456:abcdef"
        end

        it { is_expected.to include(error) }
      end
    end
  end

  context 'data_from_password_data' do
    subject(:data_from_password_data) do
      described_class.data_from_password_data(password_data)
    end

    let(:password_data) do
      FactoryBot.generate :metasploit_credential_password_data
    end

    it 'calls lan_manager_hex_digest_from_password_data' do
      expect(described_class).to receive(:lan_manager_hex_digest_from_password_data).with(password_data).and_call_original

      data_from_password_data
    end

    it 'calls nt_lan_manager_hex_digest_from_password_data' do
      expect(described_class).to receive(:nt_lan_manager_hex_digest_from_password_data).with(password_data).and_call_original

      data_from_password_data
    end

    it "puts a ':' between lan_manager_hex_digest_from_password_data and nt_lan_manager_hex_digest_from_password_data" do
      lan_manager_hex_digest = described_class.lan_manager_hex_digest_from_password_data(password_data)
      nt_lan_manager_hex_digest = described_class.nt_lan_manager_hex_digest_from_password_data(password_data)

      expect(data_from_password_data).to eq("#{lan_manager_hex_digest}:#{nt_lan_manager_hex_digest}")
    end
  end

  context 'hex_digest' do
    subject(:hex_digest) do
      described_class.hex_digest(hash)
    end

    let(:hash) do
      "\x01"
    end

    it 'extracts String for Array<String> output by String#unpack' do
      expect(hex_digest).to be_a String
    end

    it 'is not be fixed to 32 characters' do
      # hash would have to be 16 bytes to make the hex digest 32 characters because each byte becomes two hexadecimal
      # characters
      expect(hash.length).not_to eq(16)
      expect(hex_digest.length).not_to eq(32)
    end

    it 'should be high nibble first' do
      expect(hex_digest).to eq('01')
    end
  end

  context 'lan_manager_hex_digest_from_password_data' do
    subject(:lan_manager_hex_digest_from_password_data) do
      described_class.lan_manager_hex_digest_from_password_data(password_data)
    end

    let(:password_data) do
      'password'
    end

    it 'calls Net::NTLM.lm_hash' do
      expect(Net::NTLM).to receive(:lm_hash).and_call_original

      lan_manager_hex_digest_from_password_data
    end

    it 'calls hex_digest on hash' do
      lm_hash = double('lm_hash')
      expect(Net::NTLM).to receive(:lm_hash).and_return(lm_hash)
      expect(described_class).to receive(:hex_digest).with(lm_hash)

      lan_manager_hex_digest_from_password_data
    end

    context 'with length' do
      let(:password_data) do
        'a' * password_length
      end

      context '<= 14' do
        let(:password_length) do
          Random.rand(1 .. described_class::LAN_MANAGER_MAX_CHARACTERS)
        end

        it 'matches LAN_MANAGER_HEX_DIGEST_REGEXP' do
          expect(lan_manager_hex_digest_from_password_data).to match(/\A#{described_class::LAN_MANAGER_HEX_DIGEST_REGEXP}\z/)
        end

        it 'is Net::NTLM.lm_hash converts to a hex digest' do
          lm_hash = Net::NTLM.lm_hash(password_data)
          hex_digest = lm_hash.unpack('H*').first

          expect(lan_manager_hex_digest_from_password_data).to eq(hex_digest)
        end
      end

      context '> 14' do
        let(:password_length) do
          described_class::LAN_MANAGER_MAX_CHARACTERS + 1
        end

        it 'is hex digest for empty string' do
          expect(lan_manager_hex_digest_from_password_data).to eq('aad3b435b51404eeaad3b435b51404ee')
        end
      end
    end
  end

  context 'nt_lan_manager_hex_digest_from_password_data' do
    subject(:nt_lan_manager_hex_digest_from_password_data) do
      described_class.nt_lan_manager_hex_digest_from_password_data(password_data)
    end

    let(:password_data) do
      'password'
    end

    it 'calls Net::NTLM.ntlm_hash' do
      expect(Net::NTLM).to receive(:ntlm_hash).and_call_original

      nt_lan_manager_hex_digest_from_password_data
    end

    it 'calls hex_digest on hash' do
      ntlm_hash = double('ntlm_hash')
      expect(Net::NTLM).to receive(:ntlm_hash).and_return(ntlm_hash)
      expect(described_class).to receive(:hex_digest).with(ntlm_hash)

      nt_lan_manager_hex_digest_from_password_data
    end
  end

  context 'human name' do
    it 'properly determines the model\'s human name' do
      expect(Metasploit::Credential::NTLMHash.model_name.human).to eq('NTLM hash')
    end
  end

  context 'hash meta-methods' do
    subject(:blank_password_hash) do
      described_class.new(
          data:  described_class.data_from_password_data('')
      )
    end

    let(:non_blank_password) do
      described_class.new(
          data:  described_class.data_from_password_data('password')
      )
    end

    let(:no_lm_hash) do
      described_class.new(
          data: 'aad3b435b51404eeaad3b435b51404ee:4dc0249ad90ab626362050195893c788'
      )
    end

    context 'blank_password?' do

      it 'returns true if the hash is for a blank password' do
        expect(blank_password_hash.blank_password?).to eq(true)
      end

      it 'returns false if the hash is not for a blank password' do
        expect(non_blank_password.blank_password?).to eq(false)
      end

      it 'returns false if the nt hash is not blank but the lm hash is' do
        expect(no_lm_hash.blank_password?).to eq(false)
      end
    end

    context 'lm_hash_present?' do

      it 'returns false if the lm_hash is blank' do
        expect(no_lm_hash.lm_hash_present?).to eq(false)
      end

      it 'returns true if the lm_hash is not blank' do
        expect(non_blank_password.lm_hash_present?).to eq(true)
      end
    end
  end


end
