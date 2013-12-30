require 'spec_helper'

describe FangedValidator do
  subject(:validator) do
    described_class.new(
        attributes: attributes
    )
  end

  let(:attribute) do
    :driver
  end

  let(:attributes) do
    [
        attribute
    ]
  end

  context '#validate_each' do
    subject(:validate_each) do
      validator.validate_each(record, attribute, value)
    end

    #
    # lets
    #

    let(:record) do
      record_class.new
    end

    let(:record_class) do
      attribute = self.attribute

      Class.new {
        include ActiveModel::Validations

        #
        # Attributes
        #

        # @!attribute [rw] driver
        #   The UI driver
        #
        #   @return [Msf::Ui::Console::Driver]
        attr_accessor attribute

        #
        # Validations
        #

        validate attribute,
                 fanged: true

        #
        # Methods
        #

        def self.model_name
          @model_name ||= ActiveModel::Name.new(self, nil, 'RecordClass')
        end
      }
    end

    let(:defanged_error) do
      I18n.translate!('errors.messages.defanged')
    end

    #
    # Callbacks
    #

    before(:each) do
      allow(record).to receive(attribute).and_return(value)
    end

    context 'with value' do
      #
      # lets
      #

      let(:value) do
        double("value of ##{attribute}")
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(value).to receive(:defanged?).and_return(defanged)
      end

      context 'with defanged' do
        let(:defanged) do
          true
        end

        it 'adds defanged error on attribute' do
          validate_each

          expect(record.errors[attribute]).to include(defanged_error)
        end
      end

      context 'without defanged' do
        let(:defanged) do
          false
        end

        it 'does not add defanged error on attribute' do
          validate_each

          expect(record.errors[attribute]).not_to include(defanged_error)
        end
      end
    end

    context 'without value' do
      let(:value) do
        nil
      end

      it 'does not add defanged error on attribute' do
        validate_each

        expect(record.errors[attribute]).not_to include(defanged_error)
      end
    end
  end
end