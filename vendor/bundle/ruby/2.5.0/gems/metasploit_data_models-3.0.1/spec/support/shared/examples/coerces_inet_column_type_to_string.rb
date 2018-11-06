RSpec.shared_examples_for 'coerces inet column type to string' do |column|
  raise ArgumentError, 'must pass the column name' unless column

  context 'with an inet column' do
    let(:address) { '10.0.0.1' }

    before(:example) do
      subject.update_attribute column, address
    end

    it 'should cast the column as a string when fetching from the database' do
      expect(subject.send(column)).to eq(address)
    end
  end
end