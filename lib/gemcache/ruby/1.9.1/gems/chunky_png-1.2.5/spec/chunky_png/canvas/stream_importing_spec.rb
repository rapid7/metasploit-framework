require 'spec_helper'

describe ChunkyPNG::Canvas do

  describe '.from_rgb_stream' do
    it "should load an image correctly from a datastream" do
      File.open(resource_file('pixelstream.rgb')) do |stream|
        matrix = ChunkyPNG::Canvas.from_rgb_stream(240, 180, stream)
        matrix.should == reference_canvas('pixelstream_reference')
      end
    end
  end

  describe '.from_rgba_stream' do
    it "should load an image correctly from a datastream" do
      File.open(resource_file('pixelstream.rgba')) do |stream|
        matrix = ChunkyPNG::Canvas.from_rgba_stream(240, 180, stream)
        matrix.should == reference_canvas('pixelstream_reference')
      end
    end
  end
end
