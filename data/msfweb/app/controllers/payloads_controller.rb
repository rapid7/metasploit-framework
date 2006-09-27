class PayloadsController < ApplicationController
  layout 'windows'

  def search_complete(terms)
	search_modules(Payload.find_all(), terms)
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
