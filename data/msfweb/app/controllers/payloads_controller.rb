class PayloadsController < ApplicationController
  layout 'windows', :except => 'search'

  def search
	@results = search_modules(Payload.find_all(), params[:terms])
  end
      
  def list
    @payloads = Payload.find_all()
  end

  def view
    @payloads = Payload.find_all()
  end

  def generate
  end
  
end
