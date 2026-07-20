require 'msf/core/payload/transport_config'

RSpec.describe Msf::Payload::TransportConfig do
  subject do
    obj = Object.new
    obj.extend(Msf::Payload::TransportConfig)
    obj
  end

  def datastore_for(values)
    ds = Hash.new(nil)
    values.each { |k, v| ds[k] = v }
    ds
  end

  describe '#transport_config_bind_tcp' do
    context 'when LHOST is set' do
      it 'uses LHOST as the transport host' do
        ds = datastore_for('LHOST' => '10.0.0.1', 'LPORT' => '4444')
        config = subject.transport_config_bind_tcp(datastore: ds)
        expect(config[:lhost]).to eq('10.0.0.1')
      end
    end

    context 'when LHOST is blank and RHOST is an IPv4 address' do
      it 'binds to all IPv4 interfaces (0.0.0.0) rather than the target address' do
        ds = datastore_for('LHOST' => '', 'RHOST' => '192.168.1.10', 'LPORT' => '4444')
        config = subject.transport_config_bind_tcp(datastore: ds)
        expect(config[:lhost]).to eq('0.0.0.0')
      end

      it 'avoids a nil transport URL that breaks meterpreter initialisation' do
        ds = datastore_for('LHOST' => nil, 'RHOST' => '192.168.1.10', 'LPORT' => '4444')
        config = subject.transport_config_bind_tcp(datastore: ds)
        expect(config[:lhost]).not_to be_nil
        expect(config[:lhost]).to eq('0.0.0.0')
      end
    end

    context 'when LHOST is blank and RHOST is an IPv6 address' do
      it 'binds to all IPv6 interfaces (::)' do
        ds = datastore_for('LHOST' => '', 'RHOST' => '::1', 'LPORT' => '4444')
        config = subject.transport_config_bind_tcp(datastore: ds)
        expect(config[:lhost]).to eq('::')
      end
    end

    context 'when both LHOST and RHOST are blank' do
      it 'defaults to binding on all IPv4 interfaces (0.0.0.0)' do
        ds = datastore_for('LHOST' => nil, 'RHOST' => nil, 'LPORT' => '4444')
        config = subject.transport_config_bind_tcp(datastore: ds)
        expect(config[:lhost]).to eq('0.0.0.0')
      end
    end
  end
end
