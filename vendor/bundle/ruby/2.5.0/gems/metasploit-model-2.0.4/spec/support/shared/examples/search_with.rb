RSpec.shared_examples_for 'search_with' do |operation_class, options={}|
  name = options.fetch(:name)

  context name.to_s do
    subject(:with_operator) do
      base_class.search_with_operator_by_name[name]
    end

    it { is_expected.to be_a operation_class }

    options.each do |key, value|
      # skip :name since it use used to look up operator, so it's already been checked or with_operator would be `nil`
      unless key == :name
        it "has #{key.inspect} of #{value.inspect}" do
          expect(with_operator.send(key)).to eq(value)
        end
      end
    end

    context 'help' do
      subject(:help) do
        with_operator.help
      end

      context 'with en locale' do
        around(:example) do |example|
          I18n.with_locale(:en) do
            example.run
          end
        end

        it 'should have translation' do
          expect(help).not_to include('translation missing')
        end
      end
    end
  end
end