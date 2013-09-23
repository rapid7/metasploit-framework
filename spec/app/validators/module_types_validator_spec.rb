require 'spec_helper'

describe ModuleTypesValidator do
  subject(:module_types_validator) do
    described_class.new(
        attributes: attributes
    )
  end

  let(:attribute) do
    :module_types
  end

  let(:attributes) do
    [
        attribute
    ]
  end

  context 'CONSTANTS' do
    context 'FORMATTED_MODULE_TYPES' do
      subject(:formatted_module_types) do
        described_class::FORMATTED_MODULE_TYPES
      end

      it { should be_a String }
    end

    context 'MODULE_TYPE_SET' do
      subject(:module_type_set) do
        described_class::MODULE_TYPE_SET
      end

      it 'should be a Set of Metasploit::Model::Module::Type::ALL' do
        module_type_set.should == Set.new(Metasploit::Model::Module::Type::ALL)
      end
    end
  end

  context '#validate_each' do
    subject(:validate_each) do
      module_types_validator.validate_each(record, attribute, value)
    end

    let(:record) do
      record_class.new
    end

    let(:record_class) do
      # capture attribute name in local so it is accessible in Class block scope.
      attribute = self.attribute

      Class.new do
        include ActiveModel::Validations

        #
        # Attributes
        #

        # @!attribute [rw] module_types
        #   Module types
        #
        #   @return [Array<String>] A subset of `Metasploit::Model::Module::Type::ALL`.
        attr_accessor :module_types

        #
        # Validations
        #

        validates attribute,
                  :module_types => true

        #
        # Methods
        #

        # Needed to make anonymous Class work with errors.add.
        def self.model_name
          @model_name ||= ActiveModel::Name.new(self, nil, 'RecordClass')
        end
      end
    end

    let(:value) do
      nil
    end

    let(:blank_error) do
      I18n.translate('errors.messages.blank')
    end

    context 'with nil' do
      let(:value) do
        nil
      end

      it 'should add blank error on attribute' do
        validate_each

        record.errors[attribute].should include(blank_error)
      end
    end

    context 'with empty Array' do
      let(:value) do
        []
      end

      it 'should add blank error on attribute' do
        validate_each

        record.errors[attribute].should include(blank_error)
      end
    end

    context 'with String' do
      let(:error) do
        I18n.translate(
            'errors.messages.invalid_module_types',
            valid_module_types: described_class::FORMATTED_MODULE_TYPES
        )
      end

      let(:value) do
        # a String that is a still a module type is invalid because module_types is Array<String>
        Metasploit::Model::Module::Type::ALL.sample
      end

      it 'should add invalid_module_types error on attribute' do
        validate_each

        record.errors[attribute].should include(error)
      end
    end

    context 'with Array<String>' do
      let(:valid_module_types) do
        # 1 .. length instead of 0 .. length since there needs to be at least one module_type
        number = rand(Metasploit::Model::Module::Type::ALL.length - 1) + 1
        # random module_types
        Metasploit::Model::Module::Type::ALL.sample(number)
      end

      context 'with subset of Metasploit::Model::Module::Type::ALL' do
        let(:value) do
          valid_module_types
        end

        it 'should not add an error to attribute' do
          validate_each

          record.errors[attribute].should be_empty
        end
      end

      context 'without subset of Metasploit::Model::Module::Type::ALL' do
        let(:invalid_module_types) do
          2.times.collect { |n|
            "invalid_module_type#{n}"
          }
        end

        let(:value) do
          valid_module_types + invalid_module_types
        end

        it 'should add invalid_module_type error for each item not in Metasploit::Model::Module::Type::ALL' do
          validate_each

          invalid_module_types.each do |invalid_module_type|
            error = I18n.translate(
                'errors.messages.invalid_module_type',
                invalid_module_type: invalid_module_type,
                valid_module_types: described_class::FORMATTED_MODULE_TYPES
            )
            record.errors[attribute].should include(error)
          end
        end
      end
    end
  end
end