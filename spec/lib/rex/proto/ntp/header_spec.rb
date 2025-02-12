# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::NTP::Header::NTPShort do
  context 'in the default state' do
    describe '#to_binary_s' do
      it 'is four null bytes' do
        expect(subject.to_binary_s).to eq "\x00\x00\x00\x00".b
      end
    end

    describe '#value' do
      it 'is a BigDecimal instance' do
        expect(subject.value).to be_a(BigDecimal)
      end

      it 'is zero' do
        expect(subject.value).to eq 0
      end
    end
  end

  context 'when set to a real value' do
    let(:value) { 10.015182 }
    let(:subject) { described_class.new(value) }

    describe '#to_binary_s' do
      it 'is four null bytes' do
        expect(subject.to_binary_s).to eq "\x00\x0a\x03\xe3".b
      end
    end

    describe '#value' do
      it 'is a BigDecimal instance' do
        expect(subject.value).to be_a(BigDecimal)
      end

      it 'is the correct value' do
        expect(subject.value.round(6)).to eq value
      end
    end
  end
end

RSpec.describe Rex::Proto::NTP::Header::NTPTimestamp do
  context 'in the default state' do
    describe '#to_binary_s' do
      it 'is eight null bytes' do
        expect(subject.to_binary_s).to eq "\x00\x00\x00\x00\x00\x00\x00\x00".b
      end
    end

    describe '#value' do
      it 'is nil' do
        expect(subject.value).to be_nil
      end
    end
  end

  context 'when set to a real value' do
    let(:timestamp) { Time.parse('2024-12-12 15:32:42.555253 +0000') }
    context 'from parts' do
      let(:subject) { described_class.new.tap { |ts| ts.seconds = 0xeb05809a; ts.fraction = 0x8e2517e7 } }

      describe '#to_binary_s' do
        it 'is correct' do
          expect(subject.to_binary_s).to eq "\xeb\x05\x80\x9a\x8e\x25\x17\xe7".b
        end
      end

      describe '#value' do
        it 'is a Time instance' do
          expect(subject.value).to be_a(Time)
        end

        it 'is the correct value' do
          expect(subject.value.round(6)).to eq timestamp
        end
      end
    end

   context 'from a timestamp' do
      let(:subject) { described_class.new(timestamp) }

      describe '#to_binary_s' do
        it 'is correct' do
          expect(subject.to_binary_s).to eq "\xeb\x05\x80\x9a\x8e\x25\x0f\x84".b
        end
      end

      describe '#value' do
        it 'is a Time instance' do
          expect(subject.value).to be_a(Time)
        end

        it 'is the correct value' do
          expect(subject.value.round(6)).to eq timestamp
        end
      end
    end
  end
end

RSpec.describe Rex::Proto::NTP::Header::NTPHeader do
  context 'in the default state' do
    describe '#to_binary_s' do
      it 'is correct' do
        expect(subject.to_binary_s).to eq ("\x20".b + ("\x00".b * 47))
      end
    end

    describe '#version_number' do
      it 'is the latest supported version' do
        expect(subject.version_number).to eq 4
      end

      it 'throws an exception when set to an invalid value' do
        expect { subject.version_number = 0 }.to raise_error(BinData::ValidityError)
        expect { subject.version_number = 5 }.to raise_error(BinData::ValidityError)
      end
    end

    describe '#root_delay' do
      it 'is an NTPShort' do
        expect(subject.root_delay).to be_a Rex::Proto::NTP::Header::NTPShort
      end

      it 'is 0' do
        expect(subject.root_delay).to eq 0
      end
    end

    describe '#root_dispersion' do
      it 'is an NTPShort' do
        expect(subject.root_dispersion).to be_a Rex::Proto::NTP::Header::NTPShort
      end

      it 'is 0' do
        expect(subject.root_dispersion).to eq 0
      end
    end

    describe '#reference_id' do
      it 'is an empty string' do
        expect(subject.reference_id).to eq ''
      end
    end

    describe '#reference_timestamp' do
      it 'is an NTPTimestamp' do
        expect(subject.reference_timestamp).to be_a Rex::Proto::NTP::Header::NTPTimestamp
      end

      it 'is nil' do
        expect(subject.reference_timestamp).to eq nil
      end
    end

    describe '#origin_timestamp' do
      it 'is an NTPTimestamp' do
        expect(subject.origin_timestamp).to be_a Rex::Proto::NTP::Header::NTPTimestamp
      end

      it 'is nil' do
        expect(subject.origin_timestamp).to eq nil
      end
    end

    describe '#receive_timestamp' do
      it 'is an NTPTimestamp' do
        expect(subject.receive_timestamp).to be_a Rex::Proto::NTP::Header::NTPTimestamp
      end

      it 'is nil' do
        expect(subject.receive_timestamp).to eq nil
      end
    end

    describe '#transmit_timestamp' do
      it 'is an NTPTimestamp' do
        expect(subject.transmit_timestamp).to be_a Rex::Proto::NTP::Header::NTPTimestamp
      end

      it 'is nil' do
        expect(subject.transmit_timestamp).to eq nil
      end
    end

    describe '#extensions' do
      it 'is empty' do
        expect(subject.extensions).to be_empty
      end
    end

    describe '#key_identifier' do
      it 'is not set' do
        expect(subject.key_identifier?).to be_falsey
      end

      it 'is zero' do
        expect(subject.key_identifier).to eq 0
      end
    end

    describe '#message_digest' do
      it 'is not set' do
        expect(subject.message_digest?).to be_falsey
      end

      it 'is empty' do
        expect(subject.message_digest).to be_empty
      end
    end
  end

  describe '#read' do
    let(:subject) { described_class.new.read(packed) }
    context 'when there is no MIC' do
      let(:packed) { "\x20" + ("\x00".b * 47) }

      describe '#key_identifier' do
        it 'is not set' do
          expect(subject.key_identifier?).to be_falsey
        end

        it 'is zero' do
          expect(subject.key_identifier).to eq 0
        end
      end

      describe '#message_digest' do
        it 'is not set' do
          expect(subject.message_digest?).to be_falsey
        end

        it 'is empty' do
          expect(subject.message_digest).to be_empty
        end
      end
    end

   context 'when there is a key identifier but no message_digest (Crypto-NAK)' do
      let(:key_identifier) { 0xdead1337 }
      let(:packed) { "\x20" + ("\x00".b * 47) + [key_identifier].pack('N') }

      describe '#key_identifier' do
        it 'is set' do
          expect(subject.key_identifier?).to be_truthy
        end

        it 'is correct' do
          expect(subject.key_identifier).to eq key_identifier
        end
      end

      describe '#message_digest' do
        it 'is not set' do
          expect(subject.message_digest?).to be_falsey
        end

        it 'is empty' do
          expect(subject.message_digest).to be_empty
        end
      end
   end

   context 'when there is a key identifier and a message digest' do
      let(:key_identifier) { 0xdead1337 }
      let(:message_digest) { (0..15).to_a }
      let(:packed) { "\x20" + ("\x00".b * 47) + [key_identifier].pack('N') + message_digest.pack('C*') }

      describe '#key_identifier' do
        it 'is set' do
          expect(subject.key_identifier?).to be_truthy
        end

        it 'is correct' do
          expect(subject.key_identifier).to eq key_identifier
        end
      end

      describe '#message_digest' do
        it 'is set' do
          expect(subject.message_digest?).to be_truthy
        end

        it 'is empty' do
          expect(subject.message_digest).to eq message_digest
        end
      end
    end
  end
end
