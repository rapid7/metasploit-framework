require 'spec_helper'

describe ChunkyPNG::Canvas::Drawing do
  
  describe '#compose_pixel' do
    subject { ChunkyPNG::Canvas.new(1, 1, ChunkyPNG::Color.rgb(200, 150, 100)) }
    
    it "should compose colors correctly" do
      subject.compose_pixel(0,0, ChunkyPNG::Color(100, 150, 200, 128))
      subject[0, 0].should == ChunkyPNG::Color(150, 150, 150)
    end
    
    it "should return the composed color" do
      subject.compose_pixel(0, 0, ChunkyPNG::Color.rgba(100, 150, 200, 128)).should == ChunkyPNG::Color.rgb(150, 150, 150)
    end
    
    it "should do nothing when the coordinates are out of bounds" do
      subject.compose_pixel(1, -1, :black).should be_nil
      lambda { subject.compose_pixel(1, -1, :black) }.should_not change { subject[0, 0] }
    end
  end
  
  describe '#line' do
    it "should draw lines correctly with anti-aliasing" do
      
      canvas = ChunkyPNG::Canvas.new(31, 31, ChunkyPNG::Color::WHITE)
      
      canvas.line( 0,  0, 30, 30, ChunkyPNG::Color::BLACK)
      canvas.line( 0, 30, 30,  0, ChunkyPNG::Color::BLACK)
      canvas.line(15, 30, 15,  0, ChunkyPNG::Color.rgba(200,   0,   0, 128))
      canvas.line( 0, 15, 30, 15, ChunkyPNG::Color.rgba(200,   0,   0, 128))
      canvas.line(30, 30,  0, 15, ChunkyPNG::Color.rgba(  0, 200,   0, 128), false)
      canvas.line( 0, 15, 30,  0, ChunkyPNG::Color.rgba(  0, 200,   0, 128))
      canvas.line( 0, 30, 15,  0, ChunkyPNG::Color.rgba(  0,   0, 200, 128), false)
      canvas.line(15,  0, 30, 30, ChunkyPNG::Color.rgba(  0,   0, 200, 128))

      canvas.should == reference_canvas('lines')
    end
    
    it "should draw partial lines if the coordinates are partially out of bounds" do
      canvas = ChunkyPNG::Canvas.new(1, 2, ChunkyPNG::Color::WHITE)
      canvas.line(-5, -5, 0, 0, '#000000')
      canvas.pixels.should == [ChunkyPNG::Color::BLACK, ChunkyPNG::Color::WHITE]
    end
    
    it "should return itself to allow chaining" do
      canvas = ChunkyPNG::Canvas.new(16, 16, ChunkyPNG::Color::WHITE)
      canvas.line(1, 1, 10, 10, :black).should equal(canvas)
    end
  end
  
  describe '#rect' do
    subject { ChunkyPNG::Canvas.new(16, 16, '#ffffff') }
    
    it "should draw a rectangle with the correct colors" do
      subject.rect(1, 1, 10, 10, ChunkyPNG::Color.rgba(0, 255, 0,  80), ChunkyPNG::Color.rgba(255, 0, 0, 100))
      subject.rect(5, 5, 14, 14, ChunkyPNG::Color.rgba(0, 0, 255, 160), ChunkyPNG::Color.rgba(255, 255, 0, 100))
      subject.should == reference_canvas('rect')
    end
    
    it "should return itself to allow chaining" do
      subject.rect(1, 1, 10, 10).should equal(subject)
    end
    
    it "should draw partial rectangles if the coordinates are partially out of bounds" do
      subject.rect(0, 0, 20, 20, :black, :white)
      subject[0, 0].should == ChunkyPNG::Color::BLACK
    end
    
    it "should draw the rectangle fill only if the coordinates are fully out of bounds" do
      subject.rect(-1, -1, 20, 20, :black, :white)
      subject[0, 0].should == ChunkyPNG::Color::WHITE
    end
  end
  
  describe '#circle' do
    subject { ChunkyPNG::Canvas.new(32, 32, ChunkyPNG::Color.rgba(0, 0, 255, 128)) } 
    
    it "should draw circles" do
      subject.circle(11, 11, 10, ChunkyPNG::Color('red @ 0.5'), ChunkyPNG::Color('white @ 0.2'))
      subject.circle(21, 21, 10, ChunkyPNG::Color('green @ 0.5'))
      subject.should == reference_canvas('circles')
    end
    
    it "should draw partial circles when going of the canvas bounds" do
      subject.circle(0, 0, 10, ChunkyPNG::Color(:red))
      subject.circle(31, 16, 10, ChunkyPNG::Color(:black), ChunkyPNG::Color(:white, 0xaa))
      subject.should == reference_canvas('partial_circles')
    end

    it "should return itself to allow chaining" do
      subject.circle(10, 10, 5, :red).should equal(subject)
    end
  end
  
  describe '#polygon' do
    subject { ChunkyPNG::Canvas.new(22, 22) }

    it "should draw an filled triangle when using 3 control points" do
      subject.polygon('(2,2) (20,5) (5,20)', ChunkyPNG::Color(:black, 0xaa), ChunkyPNG::Color(:red, 0x44))
      subject.should == reference_canvas('polygon_triangle_filled')
    end

    it "should draw a unfilled polygon with 6 control points" do
      subject.polygon('(2,2) (12, 1) (20,5) (18,18) (5,20) (1,12)', ChunkyPNG::Color(:black))
      subject.should == reference_canvas('polygon_unfilled')
    end
    
    it "should draw a vertically crossed filled polygon with 4 control points" do
      subject.polygon('(2,2) (21,2) (2,21) (21,21)', ChunkyPNG::Color(:black), ChunkyPNG::Color(:red))
      subject.should == reference_canvas('polygon_filled_vertical')
    end

    it "should draw a vertically crossed filled polygon with 4 control points" do
      subject.polygon('(2,2) (2,21) (21,2) (21,21)', ChunkyPNG::Color(:black), ChunkyPNG::Color(:red))
      subject.should == reference_canvas('polygon_filled_horizontal')
    end

    it "should return itself to allow chaining" do
      subject.polygon('(2,2) (20,5) (5,20)').should equal(subject)
    end
  end
  
  describe '#bezier_curve' do
    subject { ChunkyPNG::Canvas.new(24, 24, ChunkyPNG::Color::WHITE) }
    
    it "should draw a bezier curve starting at the first point" do
      subject.bezier_curve('3,20 10,10, 20,20')
      subject[3, 20].should == ChunkyPNG::Color::BLACK
    end
    
    it "should draw a bezier curve ending at the last point" do
      subject.bezier_curve('3,20 10,10, 20,20')
      subject[20, 20].should == ChunkyPNG::Color::BLACK
    end
    
    it "should draw a bezier curve with a color of green" do
      subject.bezier_curve('3,20 10,10, 20,20', :green)
      subject[3, 20].should == ChunkyPNG::Color(:green)
    end
    
    it "should draw a three point bezier curve" do
      subject.bezier_curve('1,23 12,10 23,23').should == reference_canvas('bezier_three_point')
    end
    
    it "should draw a three point bezier curve flipped" do
      subject.bezier_curve('1,1 12,15 23,1').should == reference_canvas('bezier_three_point_flipped')
    end
    
    it "should draw a four point bezier curve" do
      subject.bezier_curve('1,23 1,5 22,5 22,23').should == reference_canvas('bezier_four_point')
    end
    
    it "should draw a four point bezier curve flipped" do
      subject.bezier_curve('1,1 1,19 22,19 22,1').should == reference_canvas('bezier_four_point_flipped')
    end
    
    it "should draw a four point bezier curve with a shape of an s" do
      subject.bezier_curve('1,23 1,5 22,23 22,5').should == reference_canvas('bezier_four_point_s')
    end
    
    it "should draw a five point bezier curve" do
      subject.bezier_curve('10,23 1,10 12,5 23,10 14,23').should == reference_canvas('bezier_five_point')
    end
    
    it "should draw a six point bezier curve" do
      subject.bezier_curve('1,23 4,15 8,20 2,2 23,15 23,1').should == reference_canvas('bezier_six_point')
    end
  end
end
