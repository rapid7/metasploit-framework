
RSpec.shared_examples_for 'a module with valid metadata' do
  it 'verifies modules metadata' do

    # aggregate_failures do

    # Verify we have a instance of the module
    expect(subject).to_not be_nil

    validator = ModuleValidator.new(subject)

    validator.validate
    # expect(validator).to be_valid
    expect(validator.errors.full_messages).to be_empty
    # end
  end
end
