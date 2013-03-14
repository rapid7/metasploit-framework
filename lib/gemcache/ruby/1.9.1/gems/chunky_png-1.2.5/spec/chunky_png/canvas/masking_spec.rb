require 'spec_helper'

describe ChunkyPNG::Canvas::Masking do
  
  subject { reference_canvas('clock') }

  before(:all) do
    @theme_color      = ChunkyPNG::Color('#e10f7a')
    @new_color        = ChunkyPNG::Color('#ff0000')
    @background_color = ChunkyPNG::Color('white')
  end
  
  describe '#change_theme_color!' do
    it "should change the theme color correctly" do
      subject.change_theme_color!(@theme_color, @new_color)
      subject.should == reference_canvas('clock_updated')
    end
  end
  
  describe '#extract_mask' do
    it "should create the correct base and mask image" do
      base, mask = subject.extract_mask(@theme_color, @background_color)
      base.should == reference_canvas('clock_base')
      mask.should == reference_canvas('clock_mask')
    end
    
    it "should create a mask image with only one opaque color" do
      base, mask = subject.extract_mask(@theme_color, @background_color)
      mask.palette.opaque_palette.size.should == 1
    end
  end
  
  describe '#change_mask_color!' do
    before { @mask = reference_canvas('clock_mask') }
    
    it "should replace the mask color correctly" do
      @mask.change_mask_color!(@new_color)
      @mask.should == reference_canvas('clock_mask_updated')
    end
    
    it "should still only have one opaque color" do
      @mask.change_mask_color!(@new_color)
      @mask.palette.opaque_palette.size.should == 1
    end
    
    it "should raise an exception when the mask image has more than once color" do
      not_a_mask = reference_canvas('operations')
      lambda { not_a_mask.change_mask_color!(@new_color) }.should raise_error(ChunkyPNG::ExpectationFailed)
    end
  end
end
