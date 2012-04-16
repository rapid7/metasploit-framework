require 'spec_helper'

describe ChunkyPNG::Canvas do
  
  describe '.from_data_url' do
    it "should import an image from a data URL" do
      data_url = reference_canvas('operations').to_data_url
      ChunkyPNG::Canvas.from_data_url(data_url).should == reference_canvas('operations')
    end
    
    it "should raise an exception if the string is not a proper data URL" do
      lambda { ChunkyPNG::Canvas.from_data_url('whatever') }.should raise_error(ChunkyPNG::SignatureMismatch)
    end
  end
end
