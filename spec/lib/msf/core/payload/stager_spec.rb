require 'msf/core/payload/stager'

RSpec.describe Msf::Payload::Stager do
  subject do
    obj = Object.new
    obj.extend(described_class)
    def obj.print_warning(_msg); end
    obj
  end

  describe '#handle_connection' do
    context 'when generating the stage raises an error' do
      let(:conn) { double('conn', peerhost: '192.0.2.1', close: nil, closed?: closed) }

      before do
        allow(subject).to receive(:generate_stage).and_raise(RuntimeError, 'stage generation failed')
        allow(subject).to receive(:print_warning)
      end

      context 'when the connection is open' do
        let(:closed) { false }

        it 'prints a warning and closes the connection without raising' do
          expect { subject.handle_connection(conn) }.not_to raise_error
          expect(subject).to have_received(:print_warning).with('Failed to stage (192.0.2.1): stage generation failed')
          expect(conn).to have_received(:close)
        end
      end

      context 'when the connection is already closed' do
        let(:closed) { true }

        it 'does not close the connection again' do
          expect { subject.handle_connection(conn) }.not_to raise_error
          expect(conn).not_to have_received(:close)
        end
      end
    end
  end
end
