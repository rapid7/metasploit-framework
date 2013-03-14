require 'spec_helper'

describe ChunkyPNG::Dimension do
  subject { ChunkyPNG::Dimension.new(2, 3) }
  
  it { should respond_to(:width) }
  it { should respond_to(:height) }
  
  describe '#area' do
    it "should calculate the area correctly" do
      subject.area.should == 6
    end
  end
end

describe 'ChunkyPNG.Dimension' do
  subject { ChunkyPNG::Dimension.new(1, 2) }
  
  it "should create a dimension from a 2-item array" do
    ChunkyPNG::Dimension([1, 2]).should     == subject
    ChunkyPNG::Dimension(['1', '2']).should == subject
  end
  
  it "should create a dimension from a hash with x and y keys" do
    ChunkyPNG::Dimension(:width => 1, :height => 2).should       == subject
    ChunkyPNG::Dimension('width' => '1', 'height' => '2').should == subject
  end
  
  it "should create a dimension from a point-like string" do
    [
      ChunkyPNG::Dimension('1,2'),
      ChunkyPNG::Dimension('1   2'),
      ChunkyPNG::Dimension('(1 , 2)'),
      ChunkyPNG::Dimension("{1x2}"),
      ChunkyPNG::Dimension("[1\t2}"),
    ].all? { |point| point == subject }
  end
  
  it "should create a dimension from an object that responds to width and height" do
    mock_object = mock('Some object with width and height', :width => 1, :height => 2)
    ChunkyPNG::Dimension(mock_object).should == subject
  end
  
  it "should raise an exception if the input is not understood" do
    lambda { ChunkyPNG::Dimension(Object.new) }.should raise_error(ArgumentError)
    lambda { ChunkyPNG::Dimension(1, 2, 3) }.should raise_error(ArgumentError)
  end
end
