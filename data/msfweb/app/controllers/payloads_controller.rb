class PayloadsController < ApplicationController
  layout 'windows'
      
  def list
  end

  def view
    @payloads = Payload.find_all()
  end

  def generate
  end
  
end
