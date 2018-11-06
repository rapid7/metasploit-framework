RSpec.describe Metasploit::Model::Search::Operation::Base, type: :model do
  subject(:operation) do
    described_class.new
  end

  context 'validations' do
    context 'operator' do
      it { is_expected.to validate_presence_of(:operator) }

      context 'valid' do
        let(:errors) do
          operation.errors[:operator]
        end

        let(:error) do
          I18n.translate('errors.messages.invalid')
        end


        let(:operation) do
          described_class.new(
              :operator => operator
          )
        end

        before(:example) do
          operation.valid?
        end

        context 'with operator' do
          let(:operator) do
            double('Operator', :valid? => valid)
          end

          context 'with valid' do
            let(:valid) do
              true
            end

            it 'should not record error on operator' do
              expect(errors).not_to include(error)
            end
          end

          context 'without valid' do
            let(:valid) do
              false
            end

            it 'should record error on operator' do
              expect(errors).to include(error)
            end
          end
        end

        context 'without operator' do
          let(:operator) do
            nil
          end

          it 'should not record error on operator' do
            expect(errors).not_to include(error)
          end
        end
      end
    end
  end
end