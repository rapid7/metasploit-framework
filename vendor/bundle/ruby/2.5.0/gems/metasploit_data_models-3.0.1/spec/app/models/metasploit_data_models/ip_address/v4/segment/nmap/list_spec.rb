RSpec.describe MetasploitDataModels::IPAddress::V4::Segment::Nmap::List, type: :model do
  subject(:nmap) {
    described_class.new(
        value: formatted_value
    )
  }

  context 'CONSTANTS' do
    context 'MATCH_REGEXP' do
      subject(:match_regexp) {
        described_class::MATCH_REGEXP
      }

      it 'matches comma separated list of segment numbers and range' do
        expect(match_regexp).to match('1,2-3,4-5,6,7-8,9')
      end

      it 'does not match an Nmap IP address' do
        segment = '1,2-3,4-5,6,7-8,9'
        expect(match_regexp).not_to match(([segment]*4).join('.'))
      end
    end

    context 'RANGE_OR_NUMBER_REGEXP' do
      subject(:range_or_number_regexp) {
        described_class::RANGE_OR_NUMBER_REGEXP
      }

      it 'matches a number' do
        expect(range_or_number_regexp).to match_string_exactly('0')
      end

      it 'matches a range' do
        expect(range_or_number_regexp).to match_string_exactly('0-255')
      end
    end

    context 'REGEXP' do
      subject(:regexp) {
        described_class::REGEXP
      }

      it 'matches a number' do
        expect(regexp).to match_string_exactly('0')
      end

      it 'matches a range' do
        expect(regexp).to match_string_exactly('0-255')
      end

      it 'matches comma separated list of numbers' do
        expect(regexp).to match_string_exactly('0,1,2')
      end

      it 'matches comma separated list of ranges' do
        expect(regexp).to match_string_exactly('1-2,3-4,5-6')
      end

      it 'matches commad separated list of numbers and ranges' do
        expect(regexp).to match_string_exactly('1,2-3,4-5,6,7-8,9')
      end
    end

    context 'SEPARATOR' do
      subject(:separator) {
        described_class::SEPARATOR
      }

      it { is_expected.to eq(',') }
    end
  end

  context 'validation' do
    before(:example) do
      nmap.valid?
    end

    context 'errors on #value' do
      subject(:value_errors) {
        nmap.errors[:value]
      }

      context 'with nil' do
        let(:blank_error) {
          I18n.translate!('errors.messages.blank')
        }

        let(:formatted_value) {
          nil
        }

        it { is_expected.to include blank_error }
      end

      context 'with matching String' do
        context 'with valid elements' do
          let(:formatted_value) {
            '1,2-3'
          }

          it { is_expected.to be_empty }
        end

        context 'with invalid MetasploitDataModels::IPAddress::V4::Nmap::Range' do
          let(:error) {
            I18n.translate!(
                'metasploit.model.errors.models.metasploit_data_models/ip_address/v4/segment/nmap/list.attributes.value.element',
                element: '255-0',
                index: 1
            )
          }

          let(:formatted_value) {
            '1,255-0'
          }

          it 'says index of element that as invalid with the value' do
            expect(value_errors).to include(error)
          end
        end
      end

      context 'without matching String' do
        let(:array_error) {
          I18n.translate!('metasploit.model.errors.models.metasploit_data_models/ip_address/v4/segment/nmap/list.attributes.value.array')
        }

        let(:formatted_value) {
          'non_matching_string'
        }

        it { is_expected.to include array_error }
      end
    end
  end

  context '#to_s' do
    subject(:to_s) do
      nmap.to_s
    end

    context 'with matching formatted value' do
      let(:formatted_value) {
        '1,2-3'
      }

      it 'returns a string equal to the original formatted value' do
        expect(to_s).to eq(formatted_value)
      end
    end

    context 'without matching formatted value' do
      let(:formatted_value) {
        Set.new([1,2])
      }

      it 'returned the formatted value as a string' do
        expect(to_s).to eq(formatted_value.to_s)
      end
    end
  end

  context '#value' do
    subject(:value) {
      nmap.value
    }

    context 'with segment number' do
      let(:formatted_value) {
        number.to_s
      }

      let(:number) {
        255
      }

      it 'has correct number of elements' do
        expect(value.length).to eq(1)
      end

      context 'only element' do
        subject(:element) {
          value.first
        }

        it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Segment::Single }

        context 'MetasploitDataModels::IPAddress::V4::Segment::Single#value' do
          it 'is value from formatted_value' do
            expect(element.value).to eq(number)
          end
        end
      end
    end

    context 'with segment range' do
      let(:begin_number) {
        0
      }

      let(:end_number) {
        255
      }

      let(:formatted_value) {
        "#{begin_number}-#{end_number}"
      }

      it 'has correct number of elements' do
        expect(value.length).to eq(1)
      end

      context 'only element' do
        subject(:element) {
          value.first
        }

        it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range }

        context 'MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range#value' do
          subject(:element_value) {
            element.value
          }

          context 'MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range#begin' do
            subject(:range_begin) {
              element_value.begin
            }

            it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Segment::Single }

            context 'MetasploitDataModels::IPAddress::V4::Segment::Single#value' do
              it 'is beginning of formatted value' do
                expect(range_begin.value).to eq(begin_number)
              end
            end
          end

          context 'MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range#end' do
            subject(:range_end) {
              element_value.end
            }

            it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Segment::Single }

            context 'MetasploitDataModels::IPAddress::V4::Segment::Single#value' do
              it 'is beginning of formatted value' do
                expect(range_end.value).to eq(end_number)
              end
            end
          end
        end
      end
    end

    context 'with comma separated list of segment numbers and ranges' do
      let(:formatted_value) {
        '1,2-3,4-5,6,7'
      }

      it 'has correct number elements' do
        expect(value.length).to eq(5)
      end
    end

    context 'with additional data' do
      let(:formatted_value) {
        'additional_data1,2-3'
      }

      it 'is original formatted value' do
        expect(value).to eq(formatted_value)
      end
    end
  end
end