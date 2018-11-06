RSpec.describe Metasploit::Credential::SSHKey, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  #
  # lets
  #

  let(:key_size) do
    # key size tuned for speed.  DO NOT use for production, it is below current recommended key size of 2048
    512
  end

  context 'factories' do
    context 'metasploit_credential_dsa_key' do
      subject(:metasploit_credential_dsa_key) do
        FactoryBot.build(:metasploit_credential_dsa_key)
      end

      it { is_expected.to be_valid }

      it 'has DSA key type' do
        expect(metasploit_credential_dsa_key.data).to match(/-----BEGIN DSA PRIVATE KEY-----/)
        expect(metasploit_credential_dsa_key.send(:openssl_pkey_pkey)).to be_a OpenSSL::PKey::DSA
      end
    end

    context 'metasploit_credential_rsa_key' do
      subject(:metasploit_credential_rsa_key) do
        FactoryBot.build(:metasploit_credential_rsa_key)
      end

      it { is_expected.to be_valid }

      it 'has RSA key type' do
        expect(metasploit_credential_rsa_key.data).to match(/-----BEGIN RSA PRIVATE KEY-----/)
        expect(metasploit_credential_rsa_key.send(:openssl_pkey_pkey)).to be_a OpenSSL::PKey::RSA
      end
    end

    context 'metasploit_credential_ssh_key' do
      subject(:metasploit_credential_ssh_key) do
        FactoryBot.build(:metasploit_credential_ssh_key)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of :data }

    context 'on #data' do
      subject(:data_errors) do
        ssh_key.errors[:data]
      end

      let(:ssh_key) do
        FactoryBot.build(:metasploit_credential_ssh_key)
      end

      context '#private' do
        #
        # lets
        #

        let(:error) do
          I18n.translate!('activerecord.errors.models.metasploit/credential/ssh_key.attributes.data.not_private')
        end

        #
        # Callbacks
        #

        before(:example) do
          expect(ssh_key).to receive(:private?).and_return(private)

          ssh_key.valid?
        end

        context 'with #private?' do
          let(:private) do
            true
          end

          it { is_expected.not_to include(error) }
        end

        context 'without #private?' do
          let(:private) do
            false
          end

          it { is_expected.to include(error) }
        end
      end

      context '#readable' do
        context 'with #data' do
          context 'with error' do
            #
            # Shared Examples
            #

            shared_examples_for 'exception' do
              it 'includes error class' do
                exception_class_name = exception.class.to_s
                expect(
                    data_errors.any? { |error|
                      error.include? exception_class_name
                    }
                ).to be true
              end

              it 'includes error message' do
                exception_message = exception.to_s

                expect(
                    data_errors.any? { |error|
                      error.include? exception_message
                    }
                ).to be true
              end
            end

            #
            # Callbacks
            #

            before(:example) do
              expect(ssh_key).to receive(:openssl_pkey_pkey).and_raise(exception)

              ssh_key.valid?
            end

            context 'with ArgumentError' do
              let(:exception) do
                ArgumentError.new("Bad Argument")
              end

              it_should_behave_like 'exception'
            end

            context 'with OpenSSL::PKey::PKeyError' do
              let(:exception) do
                OpenSSL::PKey::PKeyError.new("Bad Public/Private Key")
              end

              it_should_behave_like 'exception'
            end
          end

          context 'without error' do
            before(:example) do
              ssh_key.valid?
            end

            it { is_expected.to be_empty }
          end
        end

        context 'without #data' do
          let(:error) do
            I18n.translate!('errors.messages.blank')
          end

          #
          # Callbacks
          #

          before(:example) do
            ssh_key.data = nil

            ssh_key.valid?
          end

          it { is_expected.to include(error) }
        end
      end

      context '#unencrypted' do
        #
        # lets
        #

        let(:error) do
          I18n.translate!('activerecord.errors.models.metasploit/credential/ssh_key.attributes.data.encrypted')
        end

        #
        # Callbacks
        #

        before(:example) do
          expect(ssh_key).to receive(:encrypted?).and_return(encrypted)

          ssh_key.valid?
        end

        context 'with #encrypted?' do
          let(:encrypted) do
            true
          end

          it { is_expected.to include(error) }
        end

        context 'without #encrypted' do
          let(:encrypted) do
            false
          end

          it { is_expected.not_to include(error) }
        end
      end
    end
  end

  context '#encrypted?' do
    subject(:ssh_key) do
      FactoryBot.build(
          :metasploit_credential_ssh_key,
          data: data
      )
    end

    context 'with #data' do
      #
      # Shared examples
      #

      shared_examples_for 'key type' do |key_type|
        context "with #{key_type} key" do
          let(:unencrypted_key) do
            OpenSSL::PKey.const_get(key_type).new(key_size)
          end

          context 'with encrypted' do
            let(:cipher) do
              OpenSSL::Cipher.new('AES-128-CBC')
            end

            let(:data) do
              begin
                unencrypted_key.to_pem(cipher, password)
              # TODO This error is occasionally thrown, unsure of cause:
              rescue OpenSSL::PKey::RSAError, OpenSSL::PKey::DSAError => e
                puts "#{key_type} key error encountered (cipher: #{cipher.name}, password: #{password.inspect}): #{e.backtrace}"
                raise e
              end
            end

            let(:password) do
              cipher.random_key
            end

            it { is_expected.to be_encrypted }
          end

          context 'without encrypted' do
            let(:data) do
              unencrypted_key.to_pem
            end

            it { is_expected.not_to be_encrypted }
          end
        end
      end

      it_should_behave_like 'key type', 'DSA'
      it_should_behave_like 'key type', 'RSA'
    end

    context 'without #data' do
      let(:data) do
        nil
      end

      it { is_expected.not_to be_encrypted }
    end
  end

  context '#openssl_pkey_pkey' do
    subject(:openssl_pkey_pkey) do
      ssh_key.send(:openssl_pkey_pkey)
    end

    #
    # lets
    #

    let(:ssh_key) do
      FactoryBot.build(
          :metasploit_credential_ssh_key,
          data: data
      )
    end

    context 'with data' do
      #
      # Shared examples
      #

      shared_examples_for 'key type' do |key_type|
        context "with #{key_type} key" do
          let(:unencrypted_key) do
            OpenSSL::PKey.const_get(key_type).new(key_size)
          end

          context 'without encrypted' do
            let(:data) do
              unencrypted_key.to_pem
            end

            it { is_expected.to be_a OpenSSL::PKey.const_get(key_type) }
          end
        end
      end

      it_should_behave_like 'key type', 'DSA'
      it_should_behave_like 'key type', 'RSA'
    end

    context 'without data' do
      let(:data) do
        nil
      end

      it { is_expected.to be_nil }
    end

    context 'with DSA key' do
      let(:ssh_key) do
        FactoryBot.build(:metasploit_credential_dsa_key)
      end

      it { is_expected.to be_a OpenSSL::PKey::DSA }
    end

    context 'with RSA key' do
      let(:ssh_key) do
        FactoryBot.build(:metasploit_credential_rsa_key)
      end

      it { is_expected.to be_a OpenSSL::PKey::RSA }
    end

    context 'with nil' do

    end
  end

  context '#private?' do
    subject(:ssh_key) do
      FactoryBot.build(
          :metasploit_credential_ssh_key,
          data: data
      )
    end

    context 'with #data' do
      #
      # Shared examples
      #

      shared_examples_for 'key type' do |key_type|
        context "with #{key_type} key" do
          let(:data) do
            key.to_pem
          end

          let(:private_key) do
            OpenSSL::PKey.const_get(key_type).new(key_size)
          end

          context 'with public' do
            let(:key) do
              private_key.public_key
            end

            it { is_expected.not_to be_private }
          end

          context 'with private' do
            let(:key) do
              private_key
            end

            it { is_expected.to be_private }
          end
        end
      end

      it_should_behave_like 'key type', 'DSA'
      it_should_behave_like 'key type', 'RSA'
    end

    context 'without #data' do
      let(:data) do
        nil
      end

      it { is_expected.not_to be_private }
    end
  end

  context 'human name' do
    it 'properly determines the model\'s human name' do
      expect(Metasploit::Credential::SSHKey.model_name.human).to eq('SSH key')
    end
  end
end
