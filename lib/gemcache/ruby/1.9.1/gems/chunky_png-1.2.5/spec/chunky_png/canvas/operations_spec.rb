require 'spec_helper'

describe ChunkyPNG::Canvas::Operations do
  
  subject { reference_canvas('operations') } 
  
  describe '#grayscale' do
    it "should not return itself" do
      subject.grayscale.should_not equal(subject)
    end

    it "should convert the image correctly" do
      subject.grayscale.should == reference_canvas('operations_grayscale')
    end
    
    it "should not adjust the current image" do
      lambda { subject.crop(10, 5, 4, 8) }.should_not change(subject, :pixels)
    end
  end
  
  describe '#grayscale!' do
    it "should return itself" do
      subject.grayscale!.should equal(subject)
    end

    it "should convert the image correctly" do
      subject.grayscale!
      subject.should == reference_canvas('operations_grayscale')
    end
  end  
  
  describe '#crop' do
    it "should crop the right pixels from the original canvas" do
      subject.crop(10, 5, 4, 8).should == reference_canvas('cropped')
    end
    
    it "should not return itself" do
      subject.crop(10, 5, 4, 8).should_not equal(subject)
    end
    
    it "should not adjust the current image" do
      lambda { subject.crop(10, 5, 4, 8) }.should_not change(subject, :pixels)
    end
    
    it "should raise an exception when the cropped image falls outside the oiginal image" do
      lambda { subject.crop(16, 16, 2, 2) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
  end
  
  describe '#crop!' do
    it "should crop the right pixels from the original canvas" do
      subject.crop!(10, 5, 4, 8)
      subject.should == reference_canvas('cropped')
    end
    
    it "should have a new width and height" do
      lambda { subject.crop!(10, 5, 4, 8) }.should change(subject, :dimension).
          from(ChunkyPNG::Dimension('16x16')).
          to(ChunkyPNG::Dimension('4x8'))
    end

    it "should raise an exception when the cropped image falls outside the oiginal image" do
      lambda { subject.crop!(16, 16, 2, 2) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
    
    it "should return itself" do
      subject.crop!(10, 5, 4, 8).should equal(subject)
    end
  end

  describe '#compose' do
    it "should compose pixels correctly" do
      subcanvas = ChunkyPNG::Canvas.new(4, 8, ChunkyPNG::Color.rgba(0, 0, 0, 75))
      subject.compose(subcanvas, 8, 4).should == reference_canvas('composited')
    end
    
    it "should leave the original intact" do
      subject.compose(ChunkyPNG::Canvas.new(1,1))
      subject.should == reference_canvas('operations')
    end
    
    it "should not return itself" do
      subject.compose(ChunkyPNG::Canvas.new(1,1)).should_not equal(subject)
    end    
    
    it "should raise an exception when the pixels to compose fall outside the image" do
      lambda { subject.compose(ChunkyPNG::Canvas.new(1,1), 16, 16) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
  end
  
  describe '#compose!' do
    it "should compose pixels correctly" do
      subcanvas = ChunkyPNG::Canvas.new(4, 8, ChunkyPNG::Color.rgba(0, 0, 0, 75))
      subject.compose!(subcanvas, 8, 4)
      subject.should == reference_canvas('composited')
    end
    
    it "should return itself" do
      subject.compose!(ChunkyPNG::Canvas.new(1,1)).should equal(subject)
    end
    
    it "should compose a base image and mask correctly" do
      base = reference_canvas('clock_base')
      mask = reference_canvas('clock_mask_updated')
      base.compose!(mask)
      base.should == reference_canvas('clock_updated')
    end
    
    it "should raise an exception when the pixels to compose fall outside the image" do
      lambda { subject.compose!(ChunkyPNG::Canvas.new(1,1), 16, 16) }.should raise_error(ChunkyPNG::OutOfBounds)
    end    
  end

  describe '#replace' do
    it "should replace the correct pixels" do
      subcanvas = ChunkyPNG::Canvas.new(3, 2, ChunkyPNG::Color.rgb(200, 255, 0))
      subject.replace(subcanvas, 5, 4).should == reference_canvas('replaced')
    end
    
    it "should not return itself" do
      subject.replace(ChunkyPNG::Canvas.new(1,1)).should_not equal(subject)
    end
    
    it "should leave the original intact" do
      subject.replace(ChunkyPNG::Canvas.new(1,1))
      subject.should == reference_canvas('operations')
    end
    
    it "should raise an exception when the pixels to replace fall outside the image" do
      lambda { subject.replace(ChunkyPNG::Canvas.new(1,1), 16, 16) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
  end
  
  describe '#replace!' do
    it "should replace the correct pixels" do
      subcanvas = ChunkyPNG::Canvas.new(3, 2, ChunkyPNG::Color.rgb(200, 255, 0))
      subject.replace!(subcanvas, 5, 4)
      subject.should == reference_canvas('replaced')
    end
    
    it "should return itself" do
      subject.replace!(ChunkyPNG::Canvas.new(1,1)).should equal(subject)
    end
    
    it "should raise an exception when the pixels to replace fall outside the image" do
      lambda { subject.replace!(ChunkyPNG::Canvas.new(1,1), 16, 16) }.should raise_error(ChunkyPNG::OutOfBounds)
    end
  end
end

describe ChunkyPNG::Canvas::Operations do
  
  subject { ChunkyPNG::Canvas.new(2, 3, [1, 2, 3, 4, 5, 6]) }

  describe '#flip_horizontally!' do
    it "should flip the pixels horizontally in place" do
      subject.flip_horizontally!
      subject.should == ChunkyPNG::Canvas.new(2, 3, [5, 6, 3, 4, 1, 2])
    end
    
    it "should return itself" do
      subject.flip_horizontally!.should equal(subject)
    end
  end

  describe '#flip_horizontally' do
    it "should flip the pixels horizontally" do
      subject.flip_horizontally.should == ChunkyPNG::Canvas.new(2, 3, [5, 6, 3, 4, 1, 2])
    end
    
    it "should not return itself" do
      subject.flip_horizontally.should_not equal(subject)
    end
    
    it "should return a copy of itself when applied twice" do
      subject.flip_horizontally.flip_horizontally.should == subject
    end
  end
  
  describe '#flip_vertically!' do
    it "should flip the pixels vertically" do
      subject.flip_vertically!
      subject.should == ChunkyPNG::Canvas.new(2, 3, [2, 1, 4, 3, 6, 5])
    end
    
    it "should return itself" do
      subject.flip_horizontally!.should equal(subject)
    end
  end

  describe '#flip_vertically' do
    it "should flip the pixels vertically" do
      subject.flip_vertically.should == ChunkyPNG::Canvas.new(2, 3, [2, 1, 4, 3, 6, 5])
    end
    
    it "should not return itself" do
      subject.flip_horizontally.should_not equal(subject)
    end
    
    it "should return a copy of itself when applied twice" do
      subject.flip_vertically.flip_vertically.should == subject
    end
  end

  describe '#rotate_left' do
    it "should rotate the pixels 90 degrees counter-clockwise" do
      subject.rotate_left.should == ChunkyPNG::Canvas.new(3, 2, [2, 4, 6, 1, 3, 5] )
    end
    
    it "should not return itself" do
      subject.rotate_left.should_not equal(subject)
    end
    
    it "should not change the image dimensions" do
      lambda { subject.rotate_left }.should_not change(subject, :dimension)
    end
    
    it "it should rotate 180 degrees when applied twice" do
      subject.rotate_left.rotate_left.should == subject.rotate_180
    end
    
    it "it should rotate right when applied three times" do
      subject.rotate_left.rotate_left.rotate_left.should == subject.rotate_right
    end
    
    it "should return itself when applied four times" do
      subject.rotate_left.rotate_left.rotate_left.rotate_left.should == subject
    end
  end
  
  describe '#rotate_left!' do
    it "should rotate the pixels 90 degrees clockwise" do
      subject.rotate_left!
      subject.should == ChunkyPNG::Canvas.new(3, 2, [2, 4, 6, 1, 3, 5] )
    end
    
    it "should return itself" do
      subject.rotate_left!.should equal(subject)
    end
    
    it "should change the image dimensions" do
      lambda { subject.rotate_left! }.should change(subject, :dimension).from(ChunkyPNG::Dimension('2x3')).to(ChunkyPNG::Dimension('3x2'))
    end
  end

  describe '#rotate_right' do
    it "should rotate the pixels 90 degrees clockwise" do
      subject.rotate_right.should == ChunkyPNG::Canvas.new(3, 2, [5, 3, 1, 6, 4, 2] )
    end
    
    it "should not return itself" do
      subject.rotate_right.should_not equal(subject)
    end
    
    it "should not change the image dimensions" do
      lambda { subject.rotate_right }.should_not change(subject, :dimension)
    end
    
    it "it should rotate 180 degrees when applied twice" do
      subject.rotate_right.rotate_right.should == subject.rotate_180
    end
    
    it "it should rotate left when applied three times" do
      subject.rotate_right.rotate_right.rotate_right.should == subject.rotate_left
    end
    
    it "should return itself when applied four times" do
      subject.rotate_right.rotate_right.rotate_right.rotate_right.should == subject
    end
  end
  
  describe '#rotate_right!' do
    it "should rotate the pixels 90 degrees clockwise" do
      subject.rotate_right!
      subject.should == ChunkyPNG::Canvas.new(3, 2, [5, 3, 1, 6, 4, 2] )
    end
    
    it "should return itself" do
      subject.rotate_right!.should equal(subject)
    end
    
    it "should change the image dimensions" do
      lambda { subject.rotate_right! }.should change(subject, :dimension).from(ChunkyPNG::Dimension('2x3')).to(ChunkyPNG::Dimension('3x2'))
    end
  end

  describe '#rotate_180' do
    it "should rotate the pixels 180 degrees" do
      subject.rotate_180.should == ChunkyPNG::Canvas.new(2, 3, [6, 5, 4, 3, 2, 1])
    end
    
    it "should return not itself" do
      subject.rotate_180.should_not equal(subject)
    end
    
    it "should return a copy of itself when applied twice" do
      subject.rotate_180.rotate_180.should == subject
    end
  end
  
  describe '#rotate_180!' do
    it "should rotate the pixels 180 degrees" do
      subject.rotate_180!
      subject.should == ChunkyPNG::Canvas.new(2, 3, [6, 5, 4, 3, 2, 1])
    end
    
    it "should return itself" do
      subject.rotate_180!.should equal(subject)
    end
  end
end
