require 'spec_helper'

describe ChunkyPNG::Canvas do

  subject { ChunkyPNG::Canvas.new(1, 1, ChunkyPNG::Color::WHITE) }

  it { should respond_to(:width) }
  it { should respond_to(:height) }
  it { should respond_to(:pixels) }

  describe '#initialize' do
    it "should accept a single color value as background color" do
      canvas = ChunkyPNG::Canvas.new(2, 2, 'red @ 0.8')
      canvas[1, 0].should == ChunkyPNG::Color.parse('red @ 0.8')
    end
    
    it "should raise an error if the color value is not understood" do
      lambda { ChunkyPNG::Canvas.new(2, 2, :nonsense) }.should raise_error(ArgumentError)
    end
    
    it "should accept an array as initial pixel values" do
      canvas = ChunkyPNG::Canvas.new(2, 2, [1,2,3,4])
      canvas[0, 0].should == 1
      canvas[1, 0].should == 2
      canvas[0, 1].should == 3
      canvas[1, 1].should == 4
    end
    
    it "should raise an ArgumentError if the initial array does not have the correct number of elements" do
      lambda { ChunkyPNG::Canvas.new(2, 2, [1,2,3]) }.should raise_error(ArgumentError)
      lambda { ChunkyPNG::Canvas.new(2, 2, [1,2,3,4,5]) }.should raise_error(ArgumentError)      
    end
    
    it "should use a transparent background by default" do
      canvas = ChunkyPNG::Canvas.new(1, 1)
      canvas[0,0].should == ChunkyPNG::Color::TRANSPARENT
    end
  end

  describe '#dimension' do
    it "should return the dimensions as a Dimension instance" do
      subject.dimension.should == ChunkyPNG::Dimension('1x1')
    end
  end
  
  describe '#area' do
    it "should return the dimensions as two-item array" do
      subject.area.should == ChunkyPNG::Dimension('1x1').area
    end
  end

  describe '#include?' do
    it "should return true if the coordinates are within bounds, false otherwise" do
      subject.include_xy?( 0,  0).should be_true
      
      subject.include_xy?(-1,  0).should be_false
      subject.include_xy?( 1,  0).should be_false
      subject.include_xy?( 0, -1).should be_false
      subject.include_xy?( 0,  1).should be_false
      subject.include_xy?(-1, -1).should be_false
      subject.include_xy?(-1,  1).should be_false
      subject.include_xy?( 1, -1).should be_false
      subject.include_xy?( 1,  1).should be_false
    end
    
    it "should accept strings, arrays, hashes and points as well" do
      subject.should     include('0, 0')
      subject.should_not include('0, 1')
      subject.should     include([0, 0])
      subject.should_not include([0, 1])
      subject.should     include(:y => 0, :x => 0)
      subject.should_not include(:y => 1, :x => 0)
      subject.should     include(ChunkyPNG::Point.new(0, 0))
      subject.should_not include(ChunkyPNG::Point.new(0, 1))
    end
  end
  
  describe '#include_x?' do
    it "should return true if the x-coordinate is within bounds, false otherwise" do
      subject.include_x?( 0).should be_true
      subject.include_x?(-1).should be_false
      subject.include_x?( 1).should be_false
    end
  end
  
  describe '#include_y?' do
    it "should return true if the y-coordinate is within bounds, false otherwise" do
      subject.include_y?( 0).should be_true
      subject.include_y?(-1).should be_false
      subject.include_y?( 1).should be_false
    end
  end
  
  describe '#assert_xy!' do
    it "should not raise an exception if the coordinates are within bounds" do
      subject.should_receive(:include_xy?).with(0, 0).and_return(true)
      lambda { subject.send(:assert_xy!, 0, 0) }.should_not raise_error
    end
    
    it "should raise an exception if the coordinates are out of bounds bounds" do
      subject.should_receive(:include_xy?).with(0, -1).and_return(false)
      lambda { subject.send(:assert_xy!, 0, -1) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
  end
  
  describe '#assert_x!' do
    it "should not raise an exception if the x-coordinate is within bounds" do
      subject.should_receive(:include_x?).with(0).and_return(true)
      lambda { subject.send(:assert_x!, 0) }.should_not raise_error
    end
    
    it "should raise an exception if the x-coordinate is out of bounds bounds" do
      subject.should_receive(:include_y?).with(-1).and_return(false)
      lambda { subject.send(:assert_y!, -1) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
  end
  
  describe '#[]' do
    it "should return the pixel value if the coordinates are within bounds" do
      subject[0, 0].should == ChunkyPNG::Color::WHITE
    end
    
    it "should assert the coordinates to be within bounds" do
      subject.should_receive(:assert_xy!).with(0, 0)
      subject[0, 0]
    end
  end
  
  describe '#get_pixel' do
    it "should return the pixel value if the coordinates are within bounds" do
      subject.get_pixel(0, 0).should == ChunkyPNG::Color::WHITE
    end
    
    it "should not assert nor check the coordinates" do
      subject.should_not_receive(:assert_xy!)
      subject.should_not_receive(:include_xy?)
      subject.get_pixel(0, 0)
    end
  end
  
  describe '#[]=' do
    it "should change the pixel's color value" do
      lambda { subject[0, 0] = ChunkyPNG::Color::BLACK }.should change { subject[0, 0] }.from(ChunkyPNG::Color::WHITE).to(ChunkyPNG::Color::BLACK)
    end
    
    it "should assert the bounds of the image" do
      subject.should_receive(:assert_xy!).with(0, 0)
      subject[0, 0] = ChunkyPNG::Color::BLACK
    end
  end
  
  describe 'set_pixel' do
    it "should change the pixel's color value" do
      lambda { subject.set_pixel(0, 0, ChunkyPNG::Color::BLACK) }.should change { subject[0, 0] }.from(ChunkyPNG::Color::WHITE).to(ChunkyPNG::Color::BLACK)
    end
    
    it "should not assert or check the bounds of the image" do
      subject.should_not_receive(:assert_xy!)
      subject.should_not_receive(:include_xy?)
      subject.set_pixel(0, 0, ChunkyPNG::Color::BLACK)
    end
  end
  
  describe '#set_pixel_if_within_bounds' do
    it "should change the pixel's color value" do
      lambda { subject.set_pixel_if_within_bounds(0, 0, ChunkyPNG::Color::BLACK) }.should change { subject[0, 0] }.from(ChunkyPNG::Color::WHITE).to(ChunkyPNG::Color::BLACK)
    end

    it "should not assert, but only check the coordinates" do
      subject.should_not_receive(:assert_xy!)
      subject.should_receive(:include_xy?).with(0, 0)
      subject.set_pixel_if_within_bounds(0, 0, ChunkyPNG::Color::BLACK)
    end

    it "should do nothing if the coordinates are out of bounds" do
      subject.set_pixel_if_within_bounds(-1, 1, ChunkyPNG::Color::BLACK).should be_nil
      subject[0, 0].should == ChunkyPNG::Color::WHITE
    end
  end
  
  describe '#row' do
    before { @canvas = reference_canvas('operations') }

    it "should give an out of bounds exception when y-coordinate is out of bounds" do
      lambda { @canvas.row(-1) }.should raise_error(ChunkyPNG::OutOfBounds)
      lambda { @canvas.row(16) }.should raise_error(ChunkyPNG::OutOfBounds)
    end

    it "should return the correct pixels" do
      data = @canvas.row(0)
      data.should have(@canvas.width).items
      data.should == [65535, 268500991, 536936447, 805371903, 1073807359, 1342242815, 1610678271, 1879113727, 2147549183, 2415984639, 2684420095, 2952855551, 3221291007, 3489726463, 3758161919, 4026597375]
    end
  end
  
  describe '#column' do
    before { @canvas = reference_canvas('operations') }

    it "should give an out of bounds exception when x-coordinate is out of bounds" do
      lambda { @canvas.column(-1) }.should raise_error(ChunkyPNG::OutOfBounds)
      lambda { @canvas.column(16) }.should raise_error(ChunkyPNG::OutOfBounds)
    end

    it "should return the correct pixels" do
      data = @canvas.column(0)
      data.should have(@canvas.height).items
      data.should == [65535, 1114111, 2162687, 3211263, 4259839, 5308415, 6356991, 7405567, 8454143, 9502719, 10551295, 11599871, 12648447, 13697023, 14745599, 15794175]
    end
  end
  
  describe '#replace_canvas' do
    it "should change the dimension of the canvas" do
      lambda { subject.send(:replace_canvas!, 2, 2, [1,2,3,4]) }.should change(subject, :dimension).
          from(ChunkyPNG::Dimension('1x1')).to(ChunkyPNG::Dimension('2x2'))
    end
    
    it "should change the pixel array" do
      lambda { subject.send(:replace_canvas!, 2, 2, [1,2,3,4]) }.should change(subject, :pixels).
          from([ChunkyPNG::Color('white')]).to([1,2,3,4])
    end
    
    it "should return itself" do
      subject.send(:replace_canvas!, 2, 2, [1,2,3,4]).should equal(subject)
    end
  end
end
