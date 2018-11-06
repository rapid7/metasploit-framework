RSpec.describe MetasploitDataModels::IPAddress::V4::Nmap, type: :model do
  subject(:nmap) {
    described_class.new(
        value: formatted_value
    )
  }

  context 'validation' do
    before(:example) do
      nmap.valid?
    end

    context 'errors on #segments' do
      subject(:segments_errors) {
        nmap.errors[:segments]
      }

      context 'with segments' do
        context 'with invalid segment' do
          let(:error) {
            I18n.translate!(
                'metasploit.model.errors.models.metasploit_data_models/ip_address/v4/segmented.attributes.segments.segment_invalid',
                index: 0,
                segment: '5-4'
            )
          }

          let(:formatted_value) {
            '5-4.3.2.1'
          }

          it 'should include index of segment and segment value in the error' do
            expect(segments_errors).to include(error)
          end
        end

        context 'with valid segments' do
          let(:formatted_value) {
            '1.2.3.4'
          }

          it { is_expected.to be_empty }
        end
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

  context 'regexp' do
    subject(:regexp) {
      described_class.regexp
    }

    it 'matches a normal IPv4 address because they are a generate form of Nmap format' do
      expect(regexp).to match_string_exactly('1.2.3.4')
    end

    it 'matches an IPv4 Nmap address with comma separated list of numbers and ranges for each segment' do
      expect(regexp).to match_string_exactly('1,2-3.4-5,6.7,8.9-10,11-12')
    end
  end

  context '#value' do
    subject(:value) {
      nmap.value
    }

    context 'with nil' do
      let(:formatted_value) {
        nil
      }

      it { is_expected.to be_nil }
    end

    context 'with matching formatted value' do
      let(:formatted_value) {
        '1.2-3.4,5-6.7-8,9'
      }

      it 'has 4 segments' do
        expect(value.length).to eq(4)
      end

      it 'has MetasploitDataModels::IPAddress::V4::Segment::Nmap::List for segments' do
        expect(
            value.all? { |segment|
              segment.is_a? MetasploitDataModels::IPAddress::V4::Segment::Nmap::List
            }
        ).to eq(true)
      end

      it 'has segments ordered from high to low' do
        highest_segment = value[0]

        expect(highest_segment.value[0]).to be_a MetasploitDataModels::IPAddress::V4::Segment::Single
        expect(highest_segment.value[0].value).to eq(1)

        high_middle_segment = value[1]

        expect(high_middle_segment.value[0]).to be_a MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range
        expect(high_middle_segment.value[0].begin.value).to eq(2)
        expect(high_middle_segment.value[0].end.value).to eq(3)

        low_middle_segment = value[2]

        expect(low_middle_segment.value[0]).to be_a MetasploitDataModels::IPAddress::V4::Segment::Single
        expect(low_middle_segment.value[0].value).to eq(4)

        expect(low_middle_segment.value[1]).to be_a MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range
        expect(low_middle_segment.value[1].begin.value).to eq(5)
        expect(low_middle_segment.value[1].end.value).to eq(6)

        low_segment = value[3]

        expect(low_segment.value[0]).to be_a MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range
        expect(low_segment.value[0].begin.value).to eq(7)
        expect(low_segment.value[0].end.value).to eq(8)

        expect(low_segment.value[1]).to be_a MetasploitDataModels::IPAddress::V4::Segment::Single
        expect(low_segment.value[1].value).to eq(9)
      end
    end

    context 'without matching formatted value' do
      let(:formatted_value) {
        '::1'
      }

      it 'is the formated value' do
        expect(value).to eq(formatted_value)
      end
    end
  end
end