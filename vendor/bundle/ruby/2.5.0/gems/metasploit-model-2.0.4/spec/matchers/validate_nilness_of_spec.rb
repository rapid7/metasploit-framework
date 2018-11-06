RSpec.describe 'validate_nilness_of' do
  let(:record) {
    record_class.new
  }

  context 'a model with a nil validation' do
    let(:attribute) {
      :nil_thing
    }

    let(:record_class) {
      # capture attribute for Class.new scope
      attribute = self.attribute

      Class.new do
        include ActiveModel::Validations

        #
        # Attributes
        #

        attr_accessor attribute

        #
        # Validations
        #

        validates attribute,
                  nil: true
      end
    }

    it 'accepts' do
      expect(record).to validate_nilness_of(attribute)
    end

    it 'provides correct error message when negated' do
      expect {
        expect(record).not_to validate_nilness_of(attribute)
      }.to raise_error(
               RSpec::Expectations::ExpectationNotMetError,
               "Expected errors not to include 'must be nil' when #{attribute} is set"
           )
    end
  end

  context 'a model without a nil validation' do
    let(:attribute) {
      :non_nil_thing
    }

    let(:record_class) {
      # capture attribute for Class.new scope
      attribute = self.attribute

      Class.new do
        include ActiveModel::Validations

        #
        # Attributes
        #

        attr_accessor attribute
      end
    }

    it 'rejects' do
      expect(record).not_to validate_nilness_of(attribute)
    end

    it 'provides the correct failure message' do
      expect {
        expect(record).to validate_nilness_of(attribute)
      }.to raise_error(
               RSpec::Expectations::ExpectationNotMetError,
               "Expected errors to include 'must be nil' when #{attribute} is set to an arbitrary string"
           )
    end
  end
end