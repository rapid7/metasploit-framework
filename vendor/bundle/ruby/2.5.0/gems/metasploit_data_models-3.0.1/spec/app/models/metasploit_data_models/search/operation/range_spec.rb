RSpec.describe MetasploitDataModels::Search::Operation::Range, type: :model do
  subject(:range_operation) {
    described_class.new(attributes)
  }

  context 'CONSTANTS' do
    context 'SEPARATOR' do
      subject(:separator) {
        described_class::SEPARATOR
      }

      it { is_expected.to eq('-') }
    end
  end

  context 'validations' do
    #
    # lets
    #

    let(:attributes) {
      {
          value: value
      }
    }

    #
    # Callbacks
    #

    before(:example) do
      range_operation.valid?
    end

    context 'errors on #value' do
      subject(:errors) {
        range_operation.errors[:value]
      }

      context '#ordered' do
        let(:error) {
          I18n.translate!('metasploit.model.errors.models.metasploit_data_models/search/operation/range.attributes.value.order', error_attributes)
        }

        context 'with Range' do
          context 'with begin before end' do
            let(:error_attributes) {
              {
                  begin: '"1"',
                  end: '"2"'
              }
            }

            let(:value) {
              '1-2'
            }

            it { is_expected.not_to include(error) }
          end

          context 'with begin same as end' do
            let(:error_attributes) {
              {
                  begin: '"1"',
                  end: '"1"'
              }
            }

            let(:value) {
              '1-1'
            }

            it { is_expected.not_to include(error) }
          end

          context 'with begin after end' do
            let(:error_attributes) {
              {
                  begin: '"2"',
                  end: '"1"'
              }
            }

            let(:value) {
              '2-1'
            }

            it { is_expected.to include error }
          end
        end

        context 'without Range' do
          let(:error_attributes) {
            {
                begin: '"1"',
                end: '"2"'
            }
          }

          let(:value) {
            '1..2'
          }

          it { is_expected.not_to include(error) }
        end
      end

      context '#range' do
        context 'with Range' do
          let(:value) {
            '1-2'
          }

          it { is_expected.to be_empty }
        end

        context 'without Range' do
          let(:error) {
            I18n.translate!('metasploit.model.errors.models.metasploit_data_models/search/operation/range.attributes.value.range')
          }

          let(:value) {
            '1..2'
          }

          it { is_expected.to include error }
        end
      end
    end
  end

  context '#value' do
    subject(:value) {
      range_operation.value
    }

    #
    # lets
    #

    let(:attributes) {
      {
          value: formatted_value
      }
    }

    context "without '-'" do
      let(:formatted_value) {
        'a..b'
      }

      it 'returns unconvertable value' do
        expect(value).to eq(formatted_value)
      end
    end

    context "with one '-'" do
      let(:formatted_begin) {
        'a'
      }

      let(:formatted_end) {
        'b'
      }

      let(:formatted_value) {
        "#{formatted_begin}-#{formatted_end}"
      }

      it 'returns Ranges' do
        expect(value).to be_a Range
      end

      context '#begin' do
        subject(:range_begin) {
          value.begin
        }

        it "is part before '-'" do
          expect(range_begin).to eq(formatted_begin)
        end
      end

      context '#end' do
        subject(:range_end) {
          value.end
        }

        it "is part after '-'" do
          expect(range_end).to eq(formatted_end)
        end
      end
    end

    context "with multiple '-'" do
      let(:formatted_begin) {
        'a'
      }

      let(:formatted_end) {
        'b-c'
      }

      let(:formatted_value) {
        "#{formatted_begin}-#{formatted_end}"
      }

      it 'returns Ranges' do
        expect(value).to be_a Range
      end

      context '#begin' do
        subject(:range_begin) {
          value.begin
        }

        it "is part before first '-'" do
          expect(range_begin).to eq(formatted_begin)
        end
      end

      context '#end' do
        subject(:range_end) {
          value.end
        }

        it "is part after first '-'" do
          expect(range_end).to eq(formatted_end)
        end
      end
    end
  end
end