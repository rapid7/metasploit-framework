class NopsController < ApplicationController
  layout 'windows'

  def list
  end

  def view
    @nops = Nop.find_all()
  end

  def generate
  end
end
