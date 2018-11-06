# frozen_string_literal: true

RSpec.describe Array do
  describe "#place" do
    it "creates an Insertion object" do
      expect([].place('x')).to be_kind_of(Insertion)
    end

    it "allows multiple objects to be placed" do
      expect([1, 2].place('x', 'y', 'z').before(2)).to eq [1, 'x', 'y', 'z', 2]
    end
  end
end
