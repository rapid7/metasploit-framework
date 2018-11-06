RSpec.describe MetasploitDataModels::IPAddress::V4::Range, type: :model do
  subject(:range) {
    described_class.new(
        value: formatted_value
    )
  }

  #
  # lets
  #

  let(:formatted_value) {
    nil
  }

  context 'validations' do
    #
    # lets
    #

    let(:presence_error) {
      I18n.translate!('errors.messages.blank')
    }

    let(:invalid_error) {
      I18n.translate!('errors.messages.invalid')
    }

    #
    # Callbacks
    #

    before(:example) do
      range.valid?
    end

    context 'errors on #begin' do
      subject(:begin_errors) {
        range.errors[:begin]
      }

      context '#begin' do
        context 'with nil' do
          let(:formatted_value) {
            nil
          }

          it { is_expected.to include presence_error }
        end

        context 'with MetasploitDataModels::IPAddress::V4::Single' do
          context 'with valid' do
            let(:formatted_value) {
              '1.1.1.1-256.256.256.256'
            }

            it { is_expected.not_to include invalid_error }
          end

          context 'without valid' do
            let(:formatted_value) {
              '256.256.256.256-257.257.257.257'
            }

            it { is_expected.to include invalid_error }
          end
        end
      end
    end

    context 'errors on #end' do
      subject(:end_errors) {
        range.errors[:end]
      }

      context '#end' do
        context 'with nil' do
          let(:formatted_value) {
            nil
          }

          it { is_expected.to include presence_error }
        end

        context 'with MetasploitDataModels::IPAddress::V4::Single' do
          context 'with valid' do
            let(:formatted_value) {
              '256.256.256.256-1.1.1.1'
            }

            it { is_expected.not_to include invalid_error }
          end

          context 'without valid' do
            let(:formatted_value) {
              '257.257.257.257-256.256.256.256'
            }

            it { is_expected.to include invalid_error }
          end
        end
      end
    end

    context 'errors on #value' do
      subject(:value_errors) {
        range.errors[:value]
      }

      let(:error) {
        I18n.translate!(
            'metasploit.model.errors.models.metasploit_data_models/ip_address/range.attributes.value.order',
            begin: range.begin,
            end: range.end
        )
      }

      context 'with nil' do
        let(:formatted_value) {
          nil
        }

        it { is_expected.not_to include error }
      end

      context 'with incomparables' do
        let(:formatted_value) {
          'a-1'
        }

        it { is_expected.not_to include error }
      end

      context 'with numbers' do
        context 'in order' do
          let(:formatted_value) {
            '1.1.1.1-2.2.2.2'
          }

          it { is_expected.not_to include error }
        end

        context 'out of order' do
          let(:formatted_value) {
            '2.2.2.2-1.1.1.1'
          }

          it { is_expected.to include error }
        end
      end
    end
  end

  context 'match_regexp' do
    subject(:match_regexp) do
      described_class::match_regexp
    end

    it 'matches range exactly' do
      expect(match_regexp).to match_string_exactly('1.1.1.1-255.255.255.255')
    end
  end

  context 'regexp' do
    subject(:regexp) {
      described_class::regexp
    }

    it 'does not match a single IPv4 address' do
      expect(regexp).not_to match('255.255.255.255')
    end

    it 'does not match separator by itself' do
      expect(regexp).not_to match('-')
    end

    it 'does not match range with only one extreme' do
      expect(regexp).not_to match('1.1.1.1-')
      expect(regexp).not_to match('-255.255.255.255')
    end

    it 'matches range' do
      expect(regexp).to match_string_exactly('1.1.1.1-255.255.255.255')
    end
  end

  context '#to_s' do
    subject(:to_s) {
      range.to_s
    }

    context 'with Range' do
      let(:formatted_value) {
        '1.1.1.1-2.2.2.2'
      }

      it 'equals the original formatted value' do
        expect(to_s).to eq(formatted_value)
      end
    end

    context 'without Range' do
      let(:formatted_value) {
        '1..2'
      }

      it { is_expected.to eq('-') }
    end
  end

  context '#value' do
    subject(:value) {
      range.value
    }

    context 'with -' do
      context 'with extremes' do
        let(:formatted_value) {
          '1.1.1.1-2.2.2.2'
        }

        it { is_expected.to be_a Range }

        context 'Range#begin' do
          subject(:range_begin) {
            value.begin
          }

          it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Single }

          it "is value before '-'" do
            expect(range_begin).to eq(MetasploitDataModels::IPAddress::V4::Single.new(value: '1.1.1.1'))
          end
        end

        context 'Range#end' do
          subject(:range_end) {
            value.end
          }

          it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Single }

          it "is value after '-'" do
            expect(range_end).to eq(MetasploitDataModels::IPAddress::V4::Single.new(value: '2.2.2.2'))
          end
        end
      end

      context 'without extremes' do
        let(:formatted_value) {
          '-'
        }

        it { is_expected.to be_a Range }

        context 'Range#begin' do
          subject(:range_begin) {
            value.begin
          }

          it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Single }

          context 'MetasploitDataModels::IPAddress::V4::Single#value' do
            subject(:begin_value) {
              range_begin.value
            }

            it { is_expected.to eq('') }
          end
        end

        context 'Range#end' do
          subject(:range_end) {
            value.end
          }

          it { is_expected.to be_a MetasploitDataModels::IPAddress::V4::Single }

          context 'MetasploitDataModels::IPAddress::V4::Single#value' do
            subject(:end_value) {
              range_end.value
            }

            it { is_expected.to eq('') }
          end
        end
      end
    end

    context 'without -' do
      let(:formatted_value) do
        '1'
      end

      it { is_expected.not_to be_a Range }
    end
  end
end