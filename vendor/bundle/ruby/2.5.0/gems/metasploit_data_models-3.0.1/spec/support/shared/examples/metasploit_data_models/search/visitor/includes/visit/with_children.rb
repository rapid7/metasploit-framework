RSpec.shared_examples_for 'MetasploitDataModels::Search::Visitor::Includes#visit with #children' do
  let(:children) do
    2.times.collect { |n|
      double("Child #{n}")
    }
  end

  let(:node) do
    node_class.new(
        :children => children
    )
  end

  it 'should visit each child' do
    # needed for call to visit subject
    expect(visitor).to receive(:visit).with(node).and_call_original

    children.each do |child|
      expect(visitor).to receive(:visit).with(child).and_return([])
    end

    visit
  end

  it 'should return Array of all child visits' do
    child_visits = []

    expect(visitor).to receive(:visit).with(node).and_call_original

    children.each_with_index do |child, i|
      child_visit = ["Visited Child #{i}"]
      allow(visitor).to receive(:visit).with(child).and_return(child_visit)
      child_visits.concat(child_visit)
    end

    expect(visit).to eq(child_visits)
  end
end