RSpec.describe MetasploitDataModels::IPAddress::V4::Segment::Single, type: :model do
  subject(:single) {
    described_class.new(
        value: formatted_value
    )
  }

  let(:formatted_value) {
    nil
  }

  context 'validations' do
    it 'validates value is only an integer between 0 and 255 inclusive' do
      is_expected.to validate_numericality_of(:value).is_greater_than_or_equal_to(0).is_less_than_or_equal_to(255).only_integer
    end
  end

  it 'can be used in a Range' do
    expect {
      Range.new(single, single)
    }.not_to raise_error
  end

  context '#add_with_carry' do
    subject(:add_with_carry) {
      single.add_with_carry(*arguments)
    }

    let(:carry_out) {
      add_with_carry[1]
    }

    let(:segment_out) {
      add_with_carry[0]
    }

    context 'with carry' do
      let(:arguments) {
        [
            other_single,
            1
        ]
      }

      context 'with overflow' do
        let(:formatted_value) {
          '255'
        }

        let(:other_single) {
          described_class.new(value: 255)
        }

        it 'outputs a proper segment' do
          expect(segment_out).to be_a described_class
          expect(segment_out.value).to be <= 255
          expect(segment_out.value).to eq(255)
        end

        it 'outputs a carry' do
          expect(carry_out).to eq(1)
        end
      end

      context 'without overflow' do
        let(:formatted_value) {
          '254'
        }

        let(:other_single) {
          described_class.new(value: 0)
        }

        it 'outs a proper segment' do
          expect(segment_out).to be_a described_class
          expect(segment_out.value).to be <= 255
          expect(segment_out.value).to eq(255)
        end

        it 'does not output a carry' do
          expect(carry_out).to eq(0)
        end
      end
    end

    context 'without carry' do
      let(:arguments) {
        [
            other_single
        ]
      }

      context 'with overflow' do
        let(:formatted_value) {
          '255'
        }

        let(:other_single) {
          described_class.new(value: 255)
        }

        it 'outputs a proper segment' do
          expect(segment_out).to be_a described_class
          expect(segment_out.value).to be <= 255
          expect(segment_out.value).to eq(254)
        end

        it 'outputs a carry' do
          expect(carry_out).to eq(1)
        end
      end

      context 'without overflow' do
        let(:formatted_value) {
          '255'
        }

        let(:other_single) {
          described_class.new(value: 0)
        }

        it 'outs a proper segment' do
          expect(segment_out).to be_a described_class
          expect(segment_out.value).to be <= 255
          expect(segment_out.value).to eq(255)
        end

        it 'does not output a carry' do
          expect(carry_out).to eq(0)
        end
      end
    end
  end

  context 'bits' do
    subject(:bits) {
      described_class.bits
    }

    it { is_expected.to eq(8) }
  end

  context 'match_regexp' do
    subject(:match_regexp) {
      described_class.match_regexp
    }

    it 'matches segment number' do
      expect(match_regexp).to match('255')
    end

    it 'does not match segment range' do
      expect(match_regexp).not_to match('0-225')
    end
  end

  context '#<=>' do
    subject(:compare) {
      single <=> other
    }

    let(:formatted_value) {
      '1'
    }

    let(:other) {
      double('Other')
    }

    it 'compares #values' do
      other_value = double('other.value')
      single_value = double('single.value')

      expect(other).to receive(:value).and_return(other_value)
      # have to use a double because can't expect().to receive on an Integer
      expect(single).to receive(:value).and_return(single_value)
      expect(single_value).to receive(:<=>).with(other_value)

      compare
    end
  end

  context '#succ' do
    subject(:succ) {
      single.succ
    }

    context '#value' do
      context 'with nil' do
        let(:formatted_value) {
          nil
        }

        specify {
          expect {
            succ
          }.not_to raise_error
        }
      end

      context 'with number' do
        let(:formatted_value) {
          value.to_s
        }

        let(:value) {
          1
        }

        it { is_expected.to be_a described_class }

        context 'succ.value' do
          it 'is succ of #value' do
            expect(succ.value).to eq(value.succ)
          end
        end
      end

      context 'without number' do
        let(:formatted_value) {
          'a'
        }

        it { is_expected.to be_a described_class }

        context 'succ.value' do
          it 'is succ of #value' do
            expect(succ.value).to eq(single.value.succ)
          end
        end
      end
    end
  end

  context '#to_s' do
    subject(:to_s) {
      single.to_s
    }

    #
    # let
    #

    let(:value) {
      double('#value')
    }

    #
    # Callbacks
    #

    before(:example) do
      allow(single).to receive(:value).and_return(value)
    end

    it 'delegates to #value' do
      expect(value).to receive(:to_s)

      to_s
    end
  end

  context '#value' do
    subject(:value) do
      single.value
    end

    context 'with Integer' do
      let(:formatted_value) do
        1
      end

      it 'should pass through Integer' do
        expect(value).to eq(formatted_value)
      end
    end

    context 'with Integer#to_s' do
      let(:formatted_value) do
        integer.to_s
      end

      let(:integer) do
        1
      end

      it 'should convert String to Integer' do
        expect(value).to eq(integer)
      end
    end

    context 'with mix text and numerals' do
      let(:formatted_value) do
        "#{integer}mix"
      end

      let(:integer) do
        123
      end

      it 'should not extract the number' do
        expect(value).not_to eq(integer)
      end

      it 'should pass through the full value' do
        expect(value).to eq(formatted_value)
      end
    end

    context 'with Float' do
      let(:formatted_value) do
        0.1
      end

      it 'should not truncate Float to Integer' do
        expect(value).not_to eq(formatted_value.to_i)
      end

      it 'should pass through Float' do
        expect(value).to eq(formatted_value)
      end
    end
  end
end