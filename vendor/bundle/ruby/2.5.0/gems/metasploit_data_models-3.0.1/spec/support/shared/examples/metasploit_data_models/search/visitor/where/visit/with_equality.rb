RSpec.shared_examples_for 'MetasploitDataModels::Search::Visitor::Where#visit with equality operation' do
  let(:node) do
    node_class.new(
        :operator => operator,
        :value => value
    )
  end

  let(:operator) do
    Metasploit::Model::Search::Operator::Attribute.new(
        # any class that responds to arel_table
        :klass => Mdm::Host
    )
  end

  let(:value) do
    "value"
  end

  it 'should visit operation.operator with attribute_visitor' do
    expect(visitor.attribute_visitor).to receive(:visit).with(operator).and_call_original

    visit
  end

  it 'should call eq on Arel::Attributes::Attribute from attribute_visitor' do
    attribute = double('Visited Operator')
    allow(visitor.attribute_visitor).to receive(:visit).with(operator).and_return(attribute)

    expect(attribute).to receive(:eq).with(value)

    visit
  end
end