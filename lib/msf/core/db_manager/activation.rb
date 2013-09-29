module Msf::DBManager::Activation
  extend ActiveSupport::Concern

  require 'msf/core/db_manager/activation/once'
  include Msf::DBManager::Activation::Once

  # Ensures that this manager is active.
  #
  # @return [void]
  def activate
    synchronize do
      unless @activated
        activate_once

        @activated = true
      end
    end
  end
end