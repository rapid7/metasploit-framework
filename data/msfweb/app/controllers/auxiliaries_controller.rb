class AuxiliariesController < ApplicationController
  layout 'windows'

  def search_complete(terms)
	search_modules(Auxiliary.find_all(), terms)
  end
    
  def list
    @auxiliaries = Auxiliary.find_all()
  end

  def view
  end

  def run
  end
end
