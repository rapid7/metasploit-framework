RSpec.shared_examples_for 'Metasploit::Credential::Search::Operation::Type' do |options={}|
  options.assert_valid_keys(:attribute, :matching_class)

  attribute = options.fetch(:attribute, :type)
  matching_class = options.fetch(:matching_class)

  context "with #{matching_class}" do
    let(:matching_class) {
      matching_class
    }

    context "with #{attribute}" do
      let(:formatted) {
        %Q{#{attribute}:"#{value}"}
      }

      context 'with Class#name' do
        let(:value) {
          matching_class.name
        }

        it 'should find only matching record' do
          expect(visit).to match_array([matching_record])
        end
      end

      context 'with Class#model_name.human' do
        let(:value) {
          matching_class.model_name.human
        }

        it 'should find only matching record' do
          expect(visit).to match_array([matching_record])
        end
      end
    end
  end
end
