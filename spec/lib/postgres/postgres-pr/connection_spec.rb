require 'postgres/postgres-pr/connection'

RSpec.describe Msf::Db::PostgresPR::Connection do
  describe '#negotiate_sasl' do
    subject { described_class.allocate }
    let(:user) { 'postgres' }
    let(:password) { 'mysecretpassword' }
    let(:server_responses) { [] }

    before(:each) do
      allow(subject).to receive(:write_message)
      read_message_mock = allow(Msf::Db::PostgresPR::Message).to receive(:read)
      read_message_mock.and_return(*server_responses) if server_responses.any?
      allow(SecureRandom).to receive(:bytes).with(32).and_return(("\x01" * 32).b)
    end

    context 'when the mechanism contains SCRAM-SHA-256' do
      context 'and the negotiation is a success' do
        let(:server_responses) do
          [
            # server-first, containing server nonce, salt, and iteration count
            Msf::Db::PostgresPR::AuthenticationSASLContinue.new(
              value: 'r=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=FUeV3rVpQpa2s8ECj3aXa6vw,s=RwsYP2UCANr95SzCJfmP4A==,i=4096'
            ),
            # server-final, server signature
            Msf::Db::PostgresPR::AuthenticationSASLFinal.new(
              value: 'v=V4CwoEsGBGMe2jGf5lpKbapnqiooWXnoyuHT3VDl6WY='
            )
          ]
        end

        it 'negotaites successfully' do
          message = Msf::Db::PostgresPR::AuthenticationSASL.new(
            mechanisms: ['SCRAM-SHA-256']
          )
          subject.negotiate_sasl(message, user, password)
          expect(subject).to have_received(:write_message).with(
            Msf::Db::PostgresPR::SaslInitialResponseMessage.new(
              mechanism: 'SCRAM-SHA-256',
              value: 'n,,n=postgres,r=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
            )
          ).ordered
          expect(subject).to have_received(:write_message).with(
            Msf::Db::PostgresPR::SASLResponseMessage.new(
              value: 'c=biws,r=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=FUeV3rVpQpa2s8ECj3aXa6vw,p=MN8FiTy5Aqut/H/TOggmlOWXHmpI/+RrnNgQFBk1eBs='
            )
          ).ordered
        end
      end

      context 'and server-final does not contain the expected calculated server proof' do
        let(:server_responses) do
          [
            # server-first, containing server nonce, salt, and iteration count
            Msf::Db::PostgresPR::AuthenticationSASLContinue.new(
              value: 'r=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=FUeV3rVpQpa2s8ECj3aXa6vw,s=RwsYP2UCANr95SzCJfmP4A==,i=4096'
            ),
            # server-final, server signature
            Msf::Db::PostgresPR::AuthenticationSASLFinal.new(
              value: 'v=invalid_server_proof'
            )
          ]
        end

        it 'raises an error' do
          message = Msf::Db::PostgresPR::AuthenticationSASL.new(
            mechanisms: ['SCRAM-SHA-256']
          )
          expect { subject.negotiate_sasl(message, user, password) }.to raise_error 'Server proof failed'
        end
      end

      context 'and the password is invalid' do
        let(:server_responses) do
          [
            # server-first, containing server nonce, salt, and iteration count
            Msf::Db::PostgresPR::AuthenticationSASLContinue.new(
              value: 'r=2kRpTcHEFyoG+UgDEpRBdVcJLTWh5WtxARhYOHcG27i7YxAi,s=GNpgixWS5E4INbrMf665Kw==,i=4096'
            ),
            # For auth failure; server-final isn't AuthenticationSASLFinal - but just a generic Postgres ErrorResponse
            Msf::Db::PostgresPR::ErrorResponse.new(
              83,
              ["FATAL", "VFATAL", "C28P01", "Mpassword authentication failed for user \"user\"", "Fauth.c", "L326", "Rauth_failed"]
            )
          ]
        end

        it 'raises an error' do
          message = Msf::Db::PostgresPR::AuthenticationSASL.new(
            mechanisms: ['SCRAM-SHA-256']
          )
          # Runtime error raised for consistency with login scanner expectations, but could be changed to a better exception in the future
          expect { subject.negotiate_sasl(message, user, password) }.to raise_error RuntimeError, "FATAL\tVFATAL\tC28P01\tMpassword authentication failed for user \"user\"\tFauth.c\tL326\tRauth_failed"
        end
      end

      context 'and a AuthenticationSASLContinue is not returned' do
        let(:server_responses) do
          [
            nil
          ]
        end
        it 'raises' do
          message = Msf::Db::PostgresPR::AuthenticationSASL.new(
            mechanisms: ['SCRAM-SHA-256']
          )
          expect { subject.negotiate_sasl(message, user, password) }.to raise_error Msf::Db::PostgresPR::AuthenticationMethodMismatch, /Did not receive AuthenticationSASLContinue/
        end
      end
    end

    context 'when the mechanism is not supported' do
      it 'raises an exception' do
        message = Msf::Db::PostgresPR::AuthenticationSASL.new(
          mechanisms: ['SCRAM-SHA-256-PLUS']
        )
        expect { subject.negotiate_sasl(message, user, password) }.to raise_error Msf::Db::PostgresPR::AuthenticationMethodMismatch, /unsupported SASL mechanisms/
      end
    end
  end
end
