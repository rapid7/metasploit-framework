# frozen_string_literal: true

RSpec.describe Hash do
  describe ".[]" do
    it "accepts an Array argument (Ruby 1.8.6 and older)" do
      list = [['foo', 'bar'], ['foo2', 'bar2']]
      expect(Hash[list]).to eq('foo' => 'bar', 'foo2' => 'bar2')
    end

    it "accepts an array as a key" do
      expect(Hash[['a', 'b'], 1]).to eq(['a', 'b'] => 1)
    end
  end
end
