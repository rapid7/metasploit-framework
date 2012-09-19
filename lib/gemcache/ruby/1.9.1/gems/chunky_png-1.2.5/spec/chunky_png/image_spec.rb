require 'spec_helper'

describe ChunkyPNG::Image do
  describe '#metadata' do
    
    it "should load metadata from an existing file" do
      image = ChunkyPNG::Image.from_file(resource_file('text_chunk.png'))
      image.metadata['Title'].should  == 'My amazing icon!'
      image.metadata['Author'].should == 'Willem van Bergen'
    end
    
    it "should write metadata to the file correctly" do
      filename = resource_file('_metadata.png')
      
      image = ChunkyPNG::Image.new(10, 10)
      image.metadata['Title']  = 'My amazing icon!'
      image.metadata['Author'] = 'Willem van Bergen'
      image.save(filename)
      
      metadata = ChunkyPNG::Datastream.from_file(filename).metadata
      metadata['Title'].should  == 'My amazing icon!'
      metadata['Author'].should == 'Willem van Bergen'
    end
  end
end