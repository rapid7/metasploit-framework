require 'spec_helper'

describe ChunkyPNG::Vector do
  subject { ChunkyPNG::Vector.new([ChunkyPNG::Point.new(2, 5), ChunkyPNG::Point.new(1, 3), ChunkyPNG::Point.new(4, 6)]) }

  it { should respond_to(:points) }
  it { should have(3).items }

  describe '#x_range' do
    it "should get the right range of x values" do
      subject.x_range.should == (1..4)
    end
    
    it "should find the minimum x-coordinate" do
      subject.min_x.should == 1
    end
    
    it "should find the maximum x-coordinate" do
      subject.max_x.should == 4
    end
    
    it "should calculate the width correctly" do
      subject.width.should == 4
    end
  end

  describe '#y_range' do
    it "should get the right range of y values" do
      subject.y_range.should == (3..6)
    end
    
    it "should find the minimum x-coordinate" do
      subject.min_y.should == 3
    end
    
    it "should find the maximum x-coordinate" do
      subject.max_y.should == 6
    end
    
    it "should calculate the height correctly" do
      subject.height.should == 4
    end
  end
  
  describe '#offset' do
    it "should return a ChunkyPNG::Point" do
      subject.offset.should be_kind_of(ChunkyPNG::Point)
    end
    
    it "should use the mininum x and y coordinates as values for the point" do
      subject.offset.x.should == subject.min_x
      subject.offset.y.should == subject.min_y
    end
  end

  describe '#dimension' do
    it "should return a ChunkyPNG::Dimension" do
      subject.dimension.should be_kind_of(ChunkyPNG::Dimension)
    end
    
    it "should use the width and height of the vector for the dimension" do
      subject.dimension.width.should == subject.width
      subject.dimension.height.should == subject.height
    end
  end

  describe '#edges' do
    it "should get three edges when closing the path" do
      subject.edges(true).to_a.should == [[ChunkyPNG::Point.new(2, 5), ChunkyPNG::Point.new(1, 3)],
                                          [ChunkyPNG::Point.new(1, 3), ChunkyPNG::Point.new(4, 6)],
                                          [ChunkyPNG::Point.new(4, 6), ChunkyPNG::Point.new(2, 5)]]
    end

    it "should get two edges when not closing the path" do
      subject.edges(false).to_a.should == [[ChunkyPNG::Point.new(2, 5), ChunkyPNG::Point.new(1, 3)],
                                           [ChunkyPNG::Point.new(1, 3), ChunkyPNG::Point.new(4, 6)]]
    end
  end
end

describe 'ChunkyPNG.Vector' do
  let(:example) { ChunkyPNG::Vector.new([ChunkyPNG::Point.new(2, 4), ChunkyPNG::Point.new(1, 2), ChunkyPNG::Point.new(3, 6)]) }
  
  it "should return an empty vector when given an empty array" do
    ChunkyPNG::Vector().should == ChunkyPNG::Vector.new([])
    ChunkyPNG::Vector(*[]).should == ChunkyPNG::Vector.new([])
  end

  it "should raise an error when an odd number of numerics is given" do
    lambda { ChunkyPNG::Vector(1, 2, 3) }.should raise_error(ArgumentError)
  end

  it "should create a vector from a string" do
    ChunkyPNG::Vector('(2,4) (1,2) (3,6)').should == example
  end
  
  it "should create a vector from a flat array" do
    ChunkyPNG::Vector(2,4,1,2,3,6).should == example
  end

  it "should create a vector from a nested array" do
    ChunkyPNG::Vector('(2,4)', [1, 2], :x => 3, :y => 6).should == example
  end
end
