require 'spec_helper'

require 'msf/base/sessions/meterpreter'

describe Msf::Sessions::Meterpreter do
  subject(:meterpreter) do
    described_class.new(
        rstream,
        options
    )
  end

  let(:options) do
    {
        # so #init_meterpreter doesn't try to pass rstream to OpenSSL.
        skip_ssl: true
    }
  end

  let(:rstream) do
    double('RStream')
  end

  context '#load_session_info' do
    subject(:load_session_info) do
      meterpreter.load_session_info
    end

    context 'database' do
      context 'with connection' do

        context 'with Mdm::Host#address' do
          context 'with database record' do
            it 'should report host'

            context 'with Mdm::Host' do
              it 'should set #session host to Mdm::Host#address'

              it 'should set #db_record Mdm::Session#host_id to Mdm::Host#id'
            end
          end
        end

        it 'should report host.os.session_fingerprint note'

        context 'with #db_record' do
          it 'should update Mdm::Session#desc'
        end

        it 'should update_host_via_sysinfo'

        context 'with Mdm::Host#address' do
          it 'should report host.nat.server note on the server host'

          it 'should report server host with firewall purpose'

          it 'should report host.nat.client note on nhost'

          it 'should report nhost with client purpose'
        end
      end

      context 'without connection' do
        it 'should set #session_host'
      end
    end
  end
end