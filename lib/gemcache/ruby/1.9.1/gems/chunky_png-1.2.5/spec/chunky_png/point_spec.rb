require 'spec_helper'

describe ChunkyPNG::Point do
  
  subject { ChunkyPNG::Point.new(1, 2) }
  
  it { should respond_to(:x) }
  it { should respond_to(:y) }
  
  describe '#within_bounds?' do
    it { should     be_within_bounds(2, 3)  }
    it { should_not be_within_bounds('1x3') }
    it { should_not be_within_bounds(2, 2) }
    it { should_not be_within_bounds('[1 2]') }
  end
  
  describe '#<=>' do
    it "should return 0 if the coordinates are identical" do
      (subject <=> ChunkyPNG::Point.new(1, 2)).should == 0
    end

    it "should return -1 if the y coordinate is smaller than the other one" do
      (subject <=> ChunkyPNG::Point.new(1, 3)).should == -1
      (subject <=> ChunkyPNG::Point.new(0, 3)).should == -1 # x doesn't matter
      (subject <=> ChunkyPNG::Point.new(2, 3)).should == -1 # x doesn't matter
    end

    it "should return 1 if the y coordinate is larger than the other one" do
      (subject <=> ChunkyPNG::Point.new(1, 0)).should == 1
      (subject <=> ChunkyPNG::Point.new(0, 0)).should == 1 # x doesn't matter
      (subject <=> ChunkyPNG::Point.new(2, 0)).should == 1 # x doesn't matter
    end

    it "should return -1 if the x coordinate is smaller and y is the same" do
      (subject <=> ChunkyPNG::Point.new(2, 2)).should == -1
    end

    it "should return 1 if the x coordinate is larger and y is the same" do
      (subject <=> ChunkyPNG::Point.new(0, 2)).should == 1
    end
  end
end

describe 'ChunkyPNG.Point' do
  subject { ChunkyPNG::Point.new(1, 2) }
  
  it "should create a point from a 2-item array" do
    ChunkyPNG::Point([1, 2]).should     == subject
    ChunkyPNG::Point(['1', '2']).should == subject
  end
  
  it "should create a point from a hash with x and y keys" do
    ChunkyPNG::Point(:x => 1, :y => 2).should       == subject
    ChunkyPNG::Point('x' => '1', 'y' => '2').should == subject
  end
  
  it "should create a point from a point-like string" do
    [
      ChunkyPNG::Point('1,2'),
      ChunkyPNG::Point('1   2'),
      ChunkyPNG::Point('(1 , 2)'),
      ChunkyPNG::Point("{1,\t2}"),
      ChunkyPNG::Point("[1 2}"),
    ].all? { |point| point == subject }
  end
  
  it "should create a point from an object that responds to x and y" do
    mock_object = mock('Some object with x and y', :x => 1, :y => 2)
    ChunkyPNG::Point(mock_object).should == subject
  end
  
  it "should raise an exception if the input is not understood" do
    lambda { ChunkyPNG::Point(Object.new) }.should raise_error(ArgumentError)
    lambda { ChunkyPNG::Point(1, 2, 3) }.should raise_error(ArgumentError)
  end
end
