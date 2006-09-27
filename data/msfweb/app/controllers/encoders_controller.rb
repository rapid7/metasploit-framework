class EncodersController < ApplicationController
  layout 'windows', :except => 'search'

  def search
	@results = search_modules(Encoder.find_all(), params[:terms])
  end
    
  def list
    @encoders = Encoder.find_all()
  end

  def view
  end

  def encode
  end
end
