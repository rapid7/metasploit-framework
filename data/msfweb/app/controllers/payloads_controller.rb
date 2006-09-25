class PayloadsController < ApplicationController
  
  def list
    @all_payloads = Payload.get_available()
  end

  def view
  end

  def generate
  end
  
end
