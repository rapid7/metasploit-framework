RSpec.describe Metasploit::Model::Search::Operation::Association, type: :model do
  subject(:operation) {
    described_class.new(
        source_operation: source_operation
    )
  }

  let(:source_operation) {
    nil
  }

  context 'validation' do
    before(:example) do
      operation.valid?
    end

    context 'errors on #source_operation' do
      subject(:source_operation_errors) {
        operation.errors[:source_operation]
      }

      let(:invalid_error) {
        I18n.translate!('errors.messages.invalid')
      }

      context 'with #source_operation' do
        let(:source_operation) {
          double('#source_operation', valid?: valid)
        }

        context 'with valid' do
          let(:valid) {
            true
          }

          it { is_expected.not_to include(invalid_error) }
        end

        context 'without valid' do
          let(:valid) {
            false
          }

          it { is_expected.to include(invalid_error) }
        end
      end

      context 'without #source_operation' do
        let(:blank_error) {
          I18n.translate!('errors.messages.blank')
        }

        let(:source_operation) {
          nil
        }

        it { is_expected.to include(blank_error) }
        it { is_expected.not_to include(invalid_error) }
      end
    end
  end

  it { is_expected.not_to respond_to :value }
  it { is_expected.not_to respond_to :value= }
end