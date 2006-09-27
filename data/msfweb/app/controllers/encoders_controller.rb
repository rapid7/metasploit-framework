class EncodersController < ApplicationController
  layout 'windows'

  def search_complete(terms)
	search_modules(Encoder.find_all(), terms)
  end
    
  def list
    @encoders = Encoder.find_all()
  end

  def view
  end

  def encode
  end
end
