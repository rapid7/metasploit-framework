require 'spec_helper'

describe 'PNG testuite' do
  
  context 'Decoding broken images' do
    png_suite_files(:broken).each do |file|
      it "should report #{File.basename(file)} as broken" do
        lambda { ChunkyPNG::Image.from_file(file) }.should raise_error(ChunkyPNG::Exception)
      end

      it "should not report #{File.basename(file)} as unsupported" do
        lambda { ChunkyPNG::Image.from_file(file) }.should_not raise_error(ChunkyPNG::NotSupported)
      end
    end
  end
  
  context 'Decoding supported images' do
    png_suite_files(:basic, '*.png').each do |file|

      reference  = file.sub(/\.png$/, '.rgba')
      color_mode = file.match(/[in](\d)[apgc](\d\d)\.png$/)[1].to_i
      bit_depth  = file.match(/[in](\d)[apgc](\d\d)\.png$/)[2].to_i
      
      it "should decode #{File.basename(file)} (color mode: #{color_mode}, bit depth: #{bit_depth}) exactly the same as the reference image" do
        decoded = ChunkyPNG::Canvas.from_file(file)
        File.open(reference, 'rb') { |f| decoded.to_rgba_stream.should == f.read }
      end
    end
  end
  
  context 'Decoding text chunks' do
    
    it "should not find metadata in a file without text chunks" do
      image = ChunkyPNG::Image.from_file(png_suite_file(:metadata, 'cm0n0g04.png'))
      image.metadata.should be_empty
    end
    
    # it "should find metadata in a file with uncompressed text chunks" do
    #   image = ChunkyPNG::Image.from_file(png_suite_file(:metadata, 'cm7n0g04.png'))
    #   image.metadata.should_not be_empty
    # end
    # 
    # it "should find metadata in a file with compressed text chunks" do
    #   image = ChunkyPNG::Image.from_file(png_suite_file(:metadata, 'cm9n0g04.png'))
    #   image.metadata.should_not be_empty
    # end
  end
  
  context 'Decoding filter methods' do
    png_suite_files(:filtering, '*_reference.png').each do |reference_file|

      file = reference_file.sub(/_reference\.png$/, '.png')
      filter_method = file.match(/f(\d\d)[a-z0-9]+\.png/)[1].to_i
      
      it "should decode #{File.basename(file)} (filter method: #{filter_method}) exactly the same as the reference image" do
        decoded   = ChunkyPNG::Canvas.from_file(file)
        reference = ChunkyPNG::Canvas.from_file(reference_file)
        decoded.should == reference
      end
    end
  end
  
  context 'Decoding different chunk splits' do
    it "should decode grayscale images successfully regardless of the data chunk ordering and splitting" do
      reference = ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi1n0g16.png')).imagedata
      ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi2n0g16.png')).imagedata.should == reference
      ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi4n0g16.png')).imagedata.should == reference
      ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi9n0g16.png')).imagedata.should == reference
    end
    
    it "should decode color images successfully regardless of the data chunk ordering and splitting" do
      reference = ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi1n2c16.png')).imagedata
      ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi2n2c16.png')).imagedata.should == reference
      ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi4n2c16.png')).imagedata.should == reference
      ChunkyPNG::Datastream.from_file(png_suite_file(:chunk_ordering, 'oi9n2c16.png')).imagedata.should == reference
    end
  end
  
  context 'Decoding different compression levels' do
    it "should decode the image successfully regardless of the compression level" do
      reference = ChunkyPNG::Datastream.from_file(png_suite_file(:compression_levels, 'z00n2c08.png')).imagedata
      ChunkyPNG::Datastream.from_file(png_suite_file(:compression_levels, 'z03n2c08.png')).imagedata.should == reference
      ChunkyPNG::Datastream.from_file(png_suite_file(:compression_levels, 'z06n2c08.png')).imagedata.should == reference
      ChunkyPNG::Datastream.from_file(png_suite_file(:compression_levels, 'z09n2c08.png')).imagedata.should == reference
    end
  end
  
  context 'Decoding transparency' do
    png_suite_files(:transparency, 'tp0*.png').each do |file|
      it "should not have transparency in #{File.basename(file)}" do
        ChunkyPNG::Color.a(ChunkyPNG::Image.from_file(file)[0,0]).should == 255
      end
    end
    
    png_suite_files(:transparency, 'tp1*.png').each do |file|
      it "should have transparency in #{File.basename(file)}" do
        ChunkyPNG::Color.a(ChunkyPNG::Image.from_file(file)[0,0]).should == 0
      end
    end
    
    png_suite_files(:transparency, 'tb*.png').each do |file|
      it "should have transparency in #{File.basename(file)}" do
        ChunkyPNG::Color.a(ChunkyPNG::Image.from_file(file)[0,0]).should == 0
      end
    end
  end
  
  context 'Decoding different sizes' do
    
    png_suite_files(:sizes, '*n*.png').each do |file|
      dimension = file.match(/s(\d\d)n\dp\d\d/)[1].to_i
      
      it "should create a canvas with a #{dimension}x#{dimension} size" do
        canvas = ChunkyPNG::Image.from_file(file)
        canvas.width.should == dimension
        canvas.height.should == dimension
      end
      
      it "should decode the #{dimension}x#{dimension} interlaced image exactly the same the non-interlaced version" do
        interlaced_file = file.sub(/n3p(\d\d)\.png$/, 'i3p\\1.png')
        ChunkyPNG::Image.from_file(interlaced_file).should == ChunkyPNG::Image.from_file(file)
      end
    end
  end
end
