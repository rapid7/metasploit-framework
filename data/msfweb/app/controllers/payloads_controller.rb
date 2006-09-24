class PayloadsController < ApplicationController
  layout 'msfweb', :except => [:list, :view, :generate]
  
  # shouldn have one but until we place a main controller, this suffices
  # why? we need a controller that holds the layout, and all others are simply
  # rendered and retrieved via AJAX requests updating the proper elements.
  # problem: old browsers won't see a flippin' thing
  def index
  end
  
  def list
  end

  def view
  end

  def generate
  end
  
end
