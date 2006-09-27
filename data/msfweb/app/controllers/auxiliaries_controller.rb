class AuxiliariesController < ApplicationController
  layout 'windows'
  
  def list
    @all_auxiliary = Auxiliary.get_available()
  end

  def view
  end

  def run
  end
end
