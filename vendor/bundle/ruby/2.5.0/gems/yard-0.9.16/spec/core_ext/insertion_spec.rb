# frozen_string_literal: true

RSpec.describe Insertion do
  describe "#before" do
    it "places an object before another" do
      expect([1, 2].place(3).before(2)).to eq [1, 3, 2]
      expect([1, 2].place(3).before(1)).to eq [3, 1, 2]
      expect([1, [4], 2].place(3).before(2)).to eq [1, [4], 3, 2]
    end
  end

  describe "#after" do
    it "places an object after another" do
      expect([1, 2].place(3).after(2)).to eq [1, 2, 3]
    end

    it "no longer places an object after another and its subsections (0.6)" do
      expect([1, [2]].place(3).after(1)).to eq [1, 3, [2]]
    end

    it "places an array after an object" do
      expect([1, 2, 3].place([4]).after(1)).to eq [1, [4], 2, 3]
    end
  end

  describe "#before_any" do
    it "places an object before another anywhere inside list (including sublists)" do
      expect([1, 2, [3]].place(4).before_any(3)).to eq [1, 2, [4, 3]]
    end
  end

  describe "#after_any" do
    it "places an object after another anywhere inside list (including sublists)" do
      expect([1, 2, [3]].place(4).after_any(3)).to eq [1, 2, [3, 4]]
    end
  end
end
