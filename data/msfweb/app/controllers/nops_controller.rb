class NopsController < ApplicationController

  def list
    @all_nops = Nop.get_available()
  end

  def view
  end

  def generate
  end
end
