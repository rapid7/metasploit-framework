RSpec.describe MetasploitDataModels::Search::Operation::Port::Range, type: :model do
  subject(:port_range_operation) {
    described_class.new(
        value: formatted_value
    )
  }

  let(:formatted_value) {
    '1'
  }

  it { is_expected.to be_a MetasploitDataModels::Search::Operation::Range }

  context 'validations' do
    before(:example) do
      port_range_operation.valid?
    end

    context 'errors on #value' do
      subject(:value_errors) {
        port_range_operation.errors[:value]
      }

      context 'with Range' do
        context 'with Integers' do
          context 'covered by MetasploitDataModels::Search::Operation::Port::Number::RANGE' do
            let(:formatted_value) {
              '1-2'
            }

            it { is_expected.to be_empty }
          end

          # this can't actually happen because the minimum is 0 and a negative number can't be parsed, but validation
          # is there in case @value is set directly.
          context 'without Range#begin covered by MetasploitDataModels::Search::Operation::Port::Number::RANGE' do
            let(:error) {
              I18n.translate!(
                  'metasploit.model.errors.models.metasploit_data_models/search/operation/port/range.attributes.value.port_range_extreme_inclusion',
                  extreme: :begin,
                  extreme_value: range_begin,
                  maximum: MetasploitDataModels::Search::Operation::Port::Number::MAXIMUM,
                  minimum: MetasploitDataModels::Search::Operation::Port::Number::MINIMUM
              )
            }

            let(:formatted_value) {
              nil
            }

            let(:port_range_operation) {
              super().tap { |port_range_operation|
                port_range_operation.instance_variable_set(:@value, Range.new(range_begin, range_end))
              }
            }

            let(:range_begin) {
              -1
            }

            let(:range_end) {
              1
            }

            it { is_expected.to include error }
          end

          context 'without Range#begin covered by MetasploitDataModels::Search::Operation::Port::Number::RANGE' do
            let(:error) {
              I18n.translate!(
                  'metasploit.model.errors.models.metasploit_data_models/search/operation/port/range.attributes.value.port_range_extreme_inclusion',
                  extreme: :end,
                  extreme_value: range_end,
                  maximum: MetasploitDataModels::Search::Operation::Port::Number::MAXIMUM,
                  minimum: MetasploitDataModels::Search::Operation::Port::Number::MINIMUM
              )
            }

            let(:formatted_value) {
              "0-#{range_end}"
            }

            let(:range_end) {
              MetasploitDataModels::Search::Operation::Port::Number::MAXIMUM + 1
            }

            it { is_expected.to include error }
          end
        end

        context 'without Integers' do
          let(:begin_error) {
            I18n.translate!(
                  'metasploit.model.errors.models.metasploit_data_models/search/operation/port/range.attributes.value.port_range_extreme_not_an_integer',
                  extreme: :begin,
                  extreme_value: range_begin
              )
          }

          let(:end_error) {
            I18n.translate!(
                'metasploit.model.errors.models.metasploit_data_models/search/operation/port/range.attributes.value.port_range_extreme_not_an_integer',
                extreme: :end,
                extreme_value: range_end
            )
          }

          let(:formatted_value) {
            "#{range_begin}-#{range_end}"
          }

          let(:range_begin) {
            'a'
          }

          let(:range_end) {
            'b'
          }

          it { is_expected.to include begin_error }
          it { is_expected.to include end_error }
        end
      end

      context 'without Range' do
        let(:error) {
          I18n.translate!('metasploit.model.errors.models.metasploit_data_models/search/operation/range.attributes.value.range')
        }

        let(:formatted_value) {
          '1'
        }

        it { is_expected.to include(error) }
      end
    end
  end
end