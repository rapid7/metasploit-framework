RSpec.shared_examples_for 'MetasploitDataModels::Search::Visitor::Includes#visit with Metasploit::Model::Search::Operation::Base' do
  let(:operator) do
    double('Operation Operator')
  end

  let(:node) do
    node_class.new(
        :operator => operator
    )
  end

  it 'should visit operator' do
    expect(visitor).to receive(:visit).with(node).and_call_original
    expect(visitor).to receive(:visit).with(operator).and_return([])

    visit
  end

  it 'should return operator visit' do
    operator_visit = ["Visited Operator"]
    expect(visitor).to receive(:visit).with(node).and_call_original
    allow(visitor).to receive(:visit).with(operator).and_return(operator_visit)

    expect(visit).to eq(operator_visit)
  end
end
