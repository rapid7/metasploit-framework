class NopsController < ApplicationController
  layout 'windows', :except => 'search'

  def search
	@results = search_modules(Nop.find_all(), params[:terms])
  end
    
  def list
    @nops = Nop.find_all()
  end

  def view
    @nops = Nop.find_all()
  end

  def generate
  end
end
