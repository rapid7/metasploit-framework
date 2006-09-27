class EncodersController < ApplicationController
  layout 'windows'
  
  def list
    @all_encoders = Encoder.get_available()
  end

  def view
  end

  def encode
  end
end
