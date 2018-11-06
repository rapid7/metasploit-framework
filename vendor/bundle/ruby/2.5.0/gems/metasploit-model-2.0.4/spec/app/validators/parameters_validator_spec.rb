RSpec.describe ParametersValidator do
  subject(:parameters_validator) do
    described_class.new(
        :attributes => attributes
    )
  end

  let(:attribute) do
    :params
  end

  let(:attributes) do
    attribute
  end

  let(:element) do
    []
  end

  let(:index) do
    rand(100)
  end

  let(:type_signature_sentence) do
    'Valid parameters are an Array<Array(String, String)>.'
  end

  context 'CONSTANTS' do
    it 'should define TYPE_SIGNATURE_SENTENCE' do
      expect(described_class::TYPE_SIGNATURE_SENTENCE).to eq(type_signature_sentence)
    end
  end

  context '#error_at' do
    subject(:error_at) do
      parameters_validator.send(
          :error_at,
          :element => element,
          :index => index,
          :prefix => prefix
      )
    end

    let(:prefix) do
      'has a prefix'
    end

    it 'should include prefix' do
      expect(error_at).to include(prefix)
    end

    it 'should include location_clause in same sentence as prefix' do
      location_clause = parameters_validator.send(
          :location_clause,
          :element => element,
          :index => index
      )

      expect(error_at).to include("#{prefix} #{location_clause}.")
    end

    it 'should include TYPE_SIGNATURE_SENTENCE' do
      expect(error_at).to include(type_signature_sentence)
    end
  end

  context '#length_error_at' do
    subject(:length_error_at) do
      parameters_validator.send(
          :length_error_at,
          :element => element,
          :extreme => extreme,
          :index => index
      )
    end

    let(:extreme) do
      [:few, :many].sample
    end

    it 'should include extreme in prefix' do
      expect(parameters_validator).to receive(:error_at) do |*args|
        options = args.first
        expect(options[:prefix]).to include(extreme.to_s)
      end

      length_error_at
    end
  end

  context '#location_clause' do
    subject(:location_clause) do
      parameters_validator.send(
          :location_clause,
          :element => element,
          :index => index
      )
    end

    it 'should include numerical index' do
      expect(location_clause).to include("at index #{index}")
    end

    it 'should include inspect of element' do
      expect(location_clause).to include(element.inspect)
    end
  end

  context '#validate_each' do
    subject(:errors) do
      record.errors[attribute]
    end

    def validate_each
      parameters_validator.validate_each(record, attribute, value)
    end

    let(:record) do
      Object.new.tap { |object|
        object.extend ActiveModel::Validations
      }
    end

    context 'with Array' do
      let(:value) do
        []
      end

      context 'element' do
        let(:value) do
          [element]
        end

        context 'with Array' do
          let(:element) do
            []
          end

          context 'with length < 2' do
            let(:element) do
              []
            end

            it 'should call #length_error_at with :extreme => :few' do
              expect(parameters_validator).to receive(:length_error_at).with(
                  hash_including(
                      :extreme => :few
                  )
              )

              validate_each
            end

            it 'should record error' do
              validate_each

              expect(errors).not_to be_empty
            end
          end

          context 'with length > 2' do
            let(:element) do
              ['', '', '']
            end

            it 'should call #length_error_at with :extreme => :many' do
              expect(parameters_validator).to receive(:length_error_at).with(
                  hash_including(
                      :extreme => :many
                  )
              )

              validate_each
            end

            it 'should record error' do
              validate_each

              expect(errors).not_to be_empty
            end
          end

          context 'with length == 2' do
            let(:element) do
              [parameter_name, parameter_value]
            end

            let(:parameter_name) do
              'parameter_name'
            end

            let(:parameter_value) do
              'parameter_value'
            end

            context 'parameter name' do
              context 'with String' do
                context 'with blank' do
                  let(:parameter_name) do
                    ''
                  end

                  it 'should call error_at with blank parameter name prefix' do
                    expect(parameters_validator).to receive(:error_at).with(
                        hash_including(
                          :prefix => 'has blank parameter name'
                        )
                    )

                    validate_each
                  end

                  it 'should record error' do
                    validate_each

                    expect(errors).not_to be_empty
                  end
                end

                context 'without blank' do
                  let(:parameter_name) do
                    'parameter_name'
                  end

                  it 'should not record error' do
                    validate_each

                    expect(errors).to be_blank
                  end
                end
              end

              context 'without String' do
                let(:parameter_name) do
                  :parameter_name
                end

                it 'should call error_at with non-String prefix' do
                  expect(parameters_validator).to receive(:error_at).with(
                      hash_including(
                          :prefix => "has non-String parameter name (#{parameter_name.inspect})"
                      )
                  )

                  validate_each
                end

                it 'should record error' do
                  validate_each

                  expect(errors).not_to be_empty
                end
              end
            end

            context 'parameter value' do
              context 'with String' do
                let(:parameter_value) do
                  'parameter_value'
                end

                it 'should not record error' do
                  validate_each

                  expect(errors).to be_blank
                end
              end

              context 'without String' do
                let(:parameter_value) do
                  0
                end

                it 'should call error_at with non-String prefix' do
                  expect(parameters_validator).to receive(:error_at).with(
                      hash_including(
                          :prefix => "has non-String parameter value (#{parameter_value.inspect})"
                      )
                  )

                  validate_each
                end

                it 'should record error' do
                  validate_each

                  expect(errors).not_to be_empty
                end
              end
            end
          end
        end

        context 'without Array' do
          let(:element) do
            {}
          end

          it 'should use #error_at with has non-Array for prefix' do
            expect(parameters_validator).to receive(:error_at).with(
                hash_including(
                    :prefix => 'has non-Array'
                )
            )

            validate_each
          end

          it 'should record error' do
            validate_each

            expect(errors).not_to be_empty
          end
        end
      end
    end

    context 'without Array' do
      let(:value) do
        ''
      end

      before(:example) do
        validate_each
      end

      it 'should error that attribute is not an array' do
        expect(
            errors.any? { |error|
              error.include? 'is not an Array.'
            }
        ).to eq(true)
      end

      it 'should include TYPE_SIGNATURE_SENTENCE' do
        errors.each do |error|
          expect(error).to include(type_signature_sentence)
        end
      end
    end
  end
end