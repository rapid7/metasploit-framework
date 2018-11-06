RSpec.describe MetasploitDataModels::IPAddress::V4::Single, type: :model do
  subject(:single) {
    described_class.new(
        value: formatted_value
    )
  }

  context 'validation' do
    before(:example) do
      single.valid?
    end

    context 'errors on #segments' do
      subject(:segments_errors) {
        single.errors[:segments]
      }

      context 'with segments' do
        let(:formatted_value) {
          '1.2.3.4'
        }

        it { is_expected.to be_empty }
      end

      context 'without segments' do
        let(:formatted_value) {
          '::1'
        }

        let(:length_error) {
          I18n.translate!(
              'metasploit.model.errors.models.metasploit_data_models/ip_address/v4/segmented.attributes.segments.wrong_length',
              count: 4
          )
        }

        it { is_expected.to include length_error }
      end
    end
  end

  context '+' do
    subject(:add) do
      single + other
    end

    context 'with MetasploitDataModels::IPAddress::V4::Single' do
      let(:other) {
        described_class.new(
            value: other_formatted_value
        )
      }

      context 'with overflow' do
        let(:formatted_value) {
          '255.255.255.255'
        }

        let(:other_formatted_value) {
          '0.0.0.1'
        }

        specify {
          expect {
            add
          }.to raise_error(ArgumentError, "255.255.255.255 + 0.0.0.1 is not a valid IP address.  It is 0.0.0.0 with a carry (1)")
        }
      end

      context 'without overflow' do
        let(:formatted_value) {
          '254.255.255.255'
        }

        context 'with ripple carry' do
          let(:other_formatted_value) {
            '0.0.0.1'
          }

          it 'propagates carry corretly' do
            expect(add).to eq(described_class.new(value: '255.0.0.0'))
          end
        end

        context 'without ripple carry' do
          let(:formatted_value) do
            '4.3.2.1'
          end

          let(:other_formatted_value) do
            '5.4.3.2'
          end

          it 'adds the correct segments together' do
            expect(add).to eq(described_class.new(value: '9.7.5.3'))
          end
        end
      end
    end

    context 'without MetasploitDataMOdels::IPAddress::V4::Single' do
      let(:formatted_value) {
          '255.255.255.255'
      }

      let(:other) {
        1
      }

      specify {
        expect {
          add
        }.to raise_error(TypeError, "Cannot add #{other.class} to #{described_class}")
      }
    end
  end

  context 'regexp' do
    subject(:regexp) {
      described_class.regexp
    }

    it 'matches a normal IPv4 address' do
      expect(regexp).to match_string_exactly('1.2.3.4')
    end

    it 'does matches an IPv4 Nmap address with comma separated list of numbers and ranges for each segment' do
      expect(regexp).not_to match_string_exactly('1,2-3.4-5,6.7,8.9-10,11-12')
    end
  end

  context '#value' do
    subject(:value) {
      single.value
    }

    context 'with nil' do
      let(:formatted_value) {
        nil
      }

      it { is_expected.to be_nil }
    end

    context 'with matching formatted value' do
      let(:formatted_value) {
        '1.2.3.4'
      }

      it 'has 4 segments' do
        expect(value.length).to eq(4)
      end

      it 'has MetasploitDataModels::IPAddress::V4::Segment::Single for segments' do
        expect(
            value.all? { |segment|
              segment.is_a? MetasploitDataModels::IPAddress::V4::Segment::Single
            }
        ).to eq(true)
      end

      it 'has segments ordered from high to low' do
        expect(value[0].value).to eq(1)
        expect(value[1].value).to eq(2)
        expect(value[2].value).to eq(3)
        expect(value[3].value).to eq(4)
      end
    end

    context 'without matching formatted value' do
      let(:formatted_value) {
        '1.2-3.5.6'
      }

      it 'is the formated value' do
        expect(value).to eq(formatted_value)
      end
    end
  end
end