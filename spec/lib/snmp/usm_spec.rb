require 'spec_helper'
require 'snmp'

RSpec.describe SNMP::UserBasedSecurityModel do
  subject(:usm) { described_class.new(**configuration) }

  let(:configuration) do
    {
      username: 'testuser',
      security_level: 'authNoPriv',
      auth_protocol: 'SHA1',
      auth_password: 'maplesyrup',
      priv_protocol: 'AES',
      priv_password: 'maplesyrup',
      context_name: ''
    }
  end

  describe 'RFC 3414 Appendix A.3 key vectors' do
    let(:engine_id) { ['000000000000000000000002'].pack('H*') }

    context 'with MD5' do
      before { configuration[:auth_protocol] = 'MD5' }

      it 'derives the expected password key' do
        key = usm.send(:password_to_key, 'maplesyrup')

        expect(key.unpack1('H*')).to eq(
          '9faf3283884e92834ebc9847d8edd963'
        )
      end

      it 'derives the expected localized key' do
        key = usm.send(:localize_key, 'maplesyrup', engine_id)

        expect(key.unpack1('H*')).to eq(
          '526f5eed9fcce26f8964c2930787d82b'
        )
      end
    end

    context 'with SHA1' do
      it 'derives the expected password key' do
        key = usm.send(:password_to_key, 'maplesyrup')

        expect(key.unpack1('H*')).to eq(
          '9fb5cc0381497b3793528939ff788d5d79145211'
        )
      end

      it 'derives the expected localized key' do
        key = usm.send(:localize_key, 'maplesyrup', engine_id)

        expect(key.unpack1('H*')).to eq(
          '6695febc9288e36282235fc7151f128497b38f3f'
        )
      end
    end
  end

  describe 'configuration validation' do
    it 'rejects an empty username' do
      configuration[:username] = ''

      expect { usm }.to raise_error(
        SNMP::InvalidSecurityParameters, /username is required/
      )
    end

    it 'rejects a short authentication passphrase' do
      configuration[:auth_password] = 'short'

      expect { usm }.to raise_error(
        SNMP::InvalidSecurityParameters, /at least 8 bytes/
      )
    end

    it 'rejects a short privacy passphrase when privacy is enabled' do
      configuration[:security_level] = 'authPriv'
      configuration[:priv_password] = 'short'

      expect { usm }.to raise_error(
        SNMP::InvalidSecurityParameters, /privacy passphrase/
      )
    end

    it 'allows noAuthNoPriv without passphrases' do
      configuration[:security_level] = 'noAuthNoPriv'
      configuration[:auth_password] = ''
      configuration[:priv_password] = ''

      expect { usm }.not_to raise_error
    end
  end
end
