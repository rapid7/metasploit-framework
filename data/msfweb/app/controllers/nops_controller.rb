class NopsController < ApplicationController
  layout 'windows'

  def search_complete(terms)
	search_modules(Nop.find_all(), terms)
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
