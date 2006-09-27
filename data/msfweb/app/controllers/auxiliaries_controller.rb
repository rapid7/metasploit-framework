class AuxiliariesController < ApplicationController
  layout 'windows', :except => 'search'

  def search
	@results = search_modules(Auxiliary.find_all(), params[:terms])
  end
    
  def list
    @auxiliaries = Auxiliary.find_all()
  end

  def view
  end

  def run
  end
end
