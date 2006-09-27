class NopsController < ApplicationController
  layout 'windows'
  
  def list
    @all_nops = Nop.get_available()
  end

  def view
  end

  def generate
  end
end
