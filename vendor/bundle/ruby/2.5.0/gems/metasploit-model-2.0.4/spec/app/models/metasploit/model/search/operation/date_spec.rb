RSpec.describe Metasploit::Model::Search::Operation::Date, type: :model do
  context 'validation' do
    context 'value' do
      before(:example) do
        operation.valid?
      end

      let(:error) do
        I18n.translate('metasploit.model.errors.models.metasploit/model/search/operation/date.attributes.value.unparseable_date')
      end

      let(:errors) do
        operation.errors[:value]
      end

      let(:operation) do
        described_class.new(:value => value)
      end

      context 'with Date' do
        let(:value) do
          Date.today
        end

        it 'should not record error' do
          expect(errors).not_to include(error)
        end
      end

      context 'without Date' do
        let(:value) do
          'not a date'
        end

        it 'should record error' do
          expect(errors).to include(error)
        end
      end
    end
  end

  context '#value' do
    subject(:value) do
      operation.value
    end

    let(:operation) do
      described_class.new(:value => formatted_value)
    end

    context 'with Date' do
      let(:formatted_value) do
        Date.today
      end

      it 'should be passed in Date' do
        expect(value).to eq(formatted_value)
      end
    end

    context 'without Date' do
      context 'with parseable' do
        let(:date) do
          Date.today
        end

        let(:formatted_value) do
          date.to_s
        end

        it 'should be parsed Date' do
          expect(value).to eq(date)
        end
      end

      context 'without parseable' do
        let(:formatted_value) do
          'not a date'
        end

        it 'should pass through value' do
          expect(value).to be formatted_value
        end
      end
    end
  end
end