RSpec.describe MetasploitDataModels::Match::Child do
  let(:extending_class) {
    # capture as local for Class.new block scope
    described_class = self.described_class

    Class.new(Metasploit::Model::Base) {
      extend described_class

      #
      # Attributes
      #

      # @!attribute value
      #   @return [String]
      attr_accessor :value
    }
  }

  before(:example) do
    stub_const('ExtendingClass', extending_class)
    stub_const('ExtendingClass::REGEXP', /\d+-\d+/)
  end

  context '#match' do
    subject(:match) {
      extending_class.match(formatted_value)
    }

    context 'formatted value' do
      context 'with matching' do
        let(:formatted_value) {
          '1-2'
        }

        it 'returns instance of extending class' do
          expect(match).to be_an extending_class
        end

        context '#value' do
          subject(:value) {
            match.value
          }

          it 'is set to formatted value' do
            expect(value).to eq(formatted_value)
          end
        end
      end

      context 'without matching' do
        let(:formatted_value) do
          '1,2-3'
        end

        it { is_expected.to be_nil }
      end
    end
  end
end