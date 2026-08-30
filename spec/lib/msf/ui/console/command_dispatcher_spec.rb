require 'rspec'

RSpec.describe Msf::Ui::Console::CommandDispatcher do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  let(:subject) do
    dummy_class = Class.new
    dummy_class.include described_class
    dummy_class.new(driver)
  end

  describe '#build_range_array' do
    [
      { input: '1', expected: [1] },
      { input: '123', expected: [123] },
      { input: '-1', expected: [-1] },
      { input: '-123', expected: [-123] },
      { input: '1,2', expected: [1, 2] },
      { input: '-1,2', expected: [-1, 2] },
      { input: '2,-1', expected: [-1, 2] },
      { input: '-1,-2', expected: [-2, -1] },
      { input: '-1-', expected: nil },
      { input: '-1-,2', expected: nil },
      { input: '-1--,2', expected: nil },
      { input: '---1', expected: nil },
      { input: '1--', expected: nil },
      { input: '1-3', expected: [1, 2, 3] },
      { input: '-1-3', expected: nil },
      { input: '-1--4', expected: nil },
      { input: '1..4', expected: [1, 2, 3, 4] },
      { input: '1..-4', expected: nil },
      { input: '-1..4', expected: nil },
      { input: '-1..-4', expected: nil },
      { input: '-1,0-3', expected: [-1, 0, 1, 2, 3] },
      { input: '-1,0,1,2', expected: [-1, 0, 1, 2] },
      { input: '-1,-1', expected: [-1] },
      { input: '-1,1..2', expected: [-1, 1, 2] }
    ].each do |test|
      it "returns #{test[:expected].inspect} for the input #{test[:input]}" do
        expect(subject.build_range_array(test[:input])).to eq(test[:expected])
      end
    end
  end
end
