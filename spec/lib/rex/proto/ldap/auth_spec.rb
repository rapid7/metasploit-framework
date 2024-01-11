# frozen_string_literal: true

require 'rex/text'
require 'rex/proto/ntlm/message'

RSpec.describe Rex::Proto::LDAP::Auth do
  subject(:nil_parameter_auth) do
    described_class.new(nil, nil, nil, nil, nil)
  end

  subject(:parameter_auth) do
    described_class.new('1122334455667788', 'my_domain', 'my_server', 'my_dnsname', 'my_dnsdomain')
  end

  before do
    @type3 = "0\x82\x01D\x02\x01\x01`\x82\x01=\x02\x01\x03\x04\x00\xA3\x82\x014\x04\nGSS-SPNEGO\x04\x82\x01$NTLMSSP\x00\x03\x00\x00\x00\x18\x00\x18\x00@"\
      "\x00\x00\x00\x92\x00\x92\x00X\x00\x00\x00\f\x00\f\x00\xEA\x00\x00\x00\b\x00\b\x00\xF6\x00\x00\x00\x16\x00\x16\x00\xFE\x00\x00\x00\x10\x00\x10"\
      "\x00\x14\x01\x00\x00\x05\x02\x80BN\x98\xF8\x84,\x8At\b\x98\xEC\xB7\xC8\x15\x12l\x01\x92\xDDO\x88<\xFA\x0F\xF4Q\x9AA\x12\xC4\x991\xE2\xA0\xCETk"\
      "\x83\x00\xCA\x8D\x01\x01\x00\x00\x00\x00\x00\x00\x80\x15sIU\t\xDA\x01\x92\xDDO\x88<\xFA\x0F\xF4\x00\x00\x00\x00\x02\x00\f\x00D\x00O\x00M\x00A\x00I\x00N"\
      "\x00\x01\x00\f\x00S\x00E\x00R\x00V\x00E\x00R\x00\x04\x00\x16\x00e\x00x\x00a\x00m\x00p\x00l\x00e\x00.\x00c\x00o\x00m\x00\x03\x00$\x00S\x00E\x00R\x00V"\
      "\x00E\x00R\x00.\x00e\x00x\x00a\x00m\x00p\x00l\x00e\x00.\x00c\x00o\x00m\x00\x00\x00\x00\x00D\x00O\x00M\x00A\x00I\x00N\x00U\x00s\x00e\x00r\x00W\x00O\x00R"\
      "\x00K\x00S\x00T\x00A\x00T\x00I\x00O\x00N\x00\xFD\xF0\x01l#bF\xD2\x87\x14\x119#c*\xBA"
  end

  let(:user_login) { OpenStruct.new }
  let(:ntlm_type1) do
    ntlm1 = Net::NTLM::Message::Type1.new.serialize

    sasl = ['GSS-SPNEGO'.to_ber, ntlm1.to_ber].to_ber_contextspecific(3)
    br = [
      Net::LDAP::Connection::LdapVersion.to_ber, ''.to_ber, sasl
    ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

    type1 = [0.to_ber, br, nil].compact.to_ber_sequence.read_ber(Net::LDAP::AsnSyntax)
    pdu = Net::LDAP::PDU.new(type1)
    pdu.bind_parameters
  end
  let(:ntlm_type3) do
    pdu = Net::LDAP::PDU.new(@type3.read_ber(Net::LDAP::AsnSyntax))
    pdu.bind_parameters
  end

  context '#initialize' do
    it 'sets default values when called with nil arguments' do
      expect(nil_parameter_auth.instance_variable_get(:@domain)).to eq('DOMAIN')
      expect(nil_parameter_auth.instance_variable_get(:@server)).to eq('SERVER')
      expect(nil_parameter_auth.instance_variable_get(:@dnsname)).to eq('server')
      expect(nil_parameter_auth.instance_variable_get(:@dnsdomain)).to eq('example.com')
      expect(nil_parameter_auth.instance_variable_get(:@challenge).length).to eq(8)
    end

    it 'sets provided values when called with arguments' do
      expect(parameter_auth.instance_variable_get(:@domain)).to eq('my_domain')
      expect(parameter_auth.instance_variable_get(:@server)).to eq('my_server')
      expect(parameter_auth.instance_variable_get(:@dnsname)).to eq('my_dnsname')
      expect(parameter_auth.instance_variable_get(:@dnsdomain)).to eq('my_dnsdomain')
      expect(parameter_auth.instance_variable_get(:@challenge).length).to eq(8)
    end
  end

  context '#handle_anonymous_request' do
    before do
      user_login.name = ''
      user_login.authentication = ''
    end

    it 'returns a hash with expected values for anonymous requests' do
      result = parameter_auth.handle_anonymous_request(user_login)

      expect(result[:user]).to eq('')
      expect(result[:pass]).to eq('')
      expect(result[:domain]).to be_nil
      expect(result[:auth_type]).to eq('Anonymous')
      expect(result[:result_code]).to eq(Net::LDAP::ResultCodeSuccess)
    end
  end

  context '#handle_simple_request' do
    it 'handles requests with an username and domain in a DN object' do
      user_login.name = 'cn=username,dc=domain,dc=com'
      user_login.authentication = 'password'

      result = parameter_auth.handle_simple_request(user_login)

      expect(result[:user]).to eq('username')
      expect(result[:domain]).to eq('domain.com')
      expect(result[:private]).to eq('password')
      expect(result[:private_type]).to eq(:password)
      expect(result[:result_code]).to eq(Net::LDAP::ResultCodeAuthMethodNotSupported)
      expect(result[:auth_type]).to eq('Simple')
    end

    it 'handles requests with an username and multiple DC components for domain in a DN object' do
      user_login.name = 'cn=username,dc=domain1,dc=domain2,dc=domain3'
      user_login.authentication = 'password'

      result = parameter_auth.handle_simple_request(user_login)

      expect(result[:user]).to eq('username')
      expect(result[:domain]).to eq('domain1.domain2.domain3')
      expect(result[:private]).to eq('password')
      expect(result[:private_type]).to eq(:password)
      expect(result[:result_code]).to eq(Net::LDAP::ResultCodeAuthMethodNotSupported)
      expect(result[:auth_type]).to eq('Simple')
    end

    it 'handles requests with information in the form of username@domain' do
      user_login.name = 'username@domain.com'
      user_login.authentication = 'password'

      result = parameter_auth.handle_simple_request(user_login)

      expect(result[:user]).to eq('username')
      expect(result[:domain]).to eq('domain.com')
      expect(result[:private]).to eq('password')
      expect(result[:private_type]).to eq(:password)
      expect(result[:result_code]).to eq(Net::LDAP::ResultCodeAuthMethodNotSupported)
      expect(result[:auth_type]).to eq('Simple')
    end

    it 'handles requests with invalid DN and CN components' do
      user_login.name = 'cn=user,name,mydomain,dc=com'
      user_login.authentication = 'password'

      expect { parameter_auth.handle_simple_request(user_login) }.to raise_error(Net::LDAP::InvalidDNError)
    end

    it 'handles requests with username and domain in NETBIOS format' do
      user_login.name = 'domain\\username'
      user_login.authentication = 'password'

      result = parameter_auth.handle_simple_request(user_login)

      expect(result[:user]).to eq('username')
      expect(result[:domain]).to eq('domain')
      expect(result[:private]).to eq('password')
      expect(result[:private_type]).to eq(:password)
      expect(result[:result_code]).to eq(Net::LDAP::ResultCodeAuthMethodNotSupported)
      expect(result[:auth_type]).to eq('Simple')
    end

    it 'handles authentication requests with incorrect request format' do
      user_login.name = 'username'
      user_login.authentication = 'password'

      result = parameter_auth.handle_simple_request(user_login)

      expect(result[:user]).to eq('username')
      expect(result[:domain]).to be_nil
      expect(result[:private]).to eq('password')
      expect(result[:private_type]).to eq(:password)
      expect(result[:result_code]).to eq(Net::LDAP::ResultCodeInvalidCredentials)
      expect(result[:auth_type]).to eq('Simple')
    end
  end

  context '#handle_sasl_request' do
    context 'using GSS-SPNEGO mechanism' do
      context 'using LM/NTLM authentication' do
        it 'handles NTLM Type1 requests with an NTLM type2 response' do
          result = parameter_auth.handle_sasl_request(ntlm_type1)

          expect(result[:server_creds]).to be_a(String)
          expect(Net::NTLM::Message.parse(result[:server_creds])).to(be_a(Net::NTLM::Message::Type2))
          expect(result[:result_code]).to eq(Net::LDAP::ResultCodeSaslBindInProgress)
          expect(result[:auth_type]).to eq('SASL')
        end

        it 'handles NTLM Type3 requests containing client information' do
          result = parameter_auth.handle_sasl_request(ntlm_type3)

          expect(result[:domain]).to eq('DOMAIN')
          expect(result[:user]).to eq('User')
          expect(result[:private]).not_to be_nil
          expect(result[:private_type]).to eq(:ntlm_hash)
          expect(result[:auth_type]).to eq('SASL')
          expect(result[:result_code]).to eq(Net::LDAP::ResultCodeAuthMethodNotSupported)
          expect(result[:auth_type]).to eq('SASL')
        end
      end

      context 'unsupprted SASL value' do
        let(:request) do
          auth_message = 'INVALIDSSP'
          sasl = ['GSS-SPNEGO'.to_ber, auth_message.to_ber].to_ber_contextspecific(3)
          br = [
            Net::LDAP::Connection::LdapVersion.to_ber, ''.to_ber, sasl
          ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

          type1 = [0.to_ber, br, nil].compact.to_ber_sequence.read_ber(Net::LDAP::AsnSyntax)
          pdu = Net::LDAP::PDU.new(type1)
          pdu.bind_parameters
        end
        it 'hanldes and unknown SASL header as unsuppoted' do
          result = parameter_auth.handle_sasl_request(request)
          expect(result[:auth_type]).to eq('SASL')
          expect(result[:result_code]).to eq(Net::LDAP::ResultCodeAuthMethodNotSupported)
        end
      end
    end
  end

  context 'private methods' do
    context '#generate_type2_response' do
      it 'returns a valid NTLM Type2 message from NTLM Type1 message' do
        message = Net::NTLM::Message.parse(ntlm_type1.authentication[1])
        result = parameter_auth.send(:generate_type2_response, message)

        expect(result).to be_a(String)
      end
    end

    context '#handle_type3_message' do
      it 'handles NTLM Type3 message and returns the expected authentication information' do
        message = Net::NTLM::Message.parse(ntlm_type3.authentication[1])
        result = parameter_auth.send(:handle_type3_message, message)

        expect(result[:domain]).to eq('DOMAIN')
        expect(result[:user]).to eq('User')
        expect(result[:private]).not_to be_nil
        expect(result[:private_type]).to eq(:ntlm_hash)
        expect(result[:ntlm_ver]).not_to be_nil
      end
    end

    context '#process_ntlm_hash' do
      it 'processes NTLM hash from Type3 message and returns the expected information' do
        ntlm_info = {
          ntlm_ver: NTLM_CONST::NTLM_V2_RESPONSE,
          lm_hash: '054ab6f7f2d60c068bf03a4e27d99834',
          lm_cli_challenge: '2464587cc5ef2d6c',
          nt_hash: '93d3aa55263a1d37931a67a5b54710b8',
          nt_cli_challenge: '0101000000000000006e8eed5507da012464587cc5ef2d6c0000000002000c004
                            4004f004d00410049004e0001000c005300450052005600450052000400160065
                            00780061006d0070006c0065002e0063006f006d0003002400530045005200560
                            0450052002e006500780061006d0070006c0065002e0063006f006d0000000000',
          domain: "D\x00O\x00M\x00A\x00I\x00N\x00",
          user: "U\x00s\x00e\x00r\x00",
          host: "W\x00O\x00R\x00K\x00S\x00T\x00A\x00T\x00I\x00O\x00N\x00"
        }

        result = parameter_auth.send(:process_ntlm_hash, ntlm_info)

        expect(result[:domain]).to eq('DOMAIN')
        expect(result[:user]).to eq('User')
        expect(result[:private]).not_to be_nil
        expect(result[:private_type]).to eq(:ntlm_hash)
        expect(result[:ntlm_ver]).not_to be_nil
      end
    end
  end
end
