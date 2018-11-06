# frozen_string_literal: true
module YARD
  module Handlers
    module Ruby
      # Handles automatic detection of dsl-style methods
      class DSLHandler < Base
        include CodeObjects
        include DSLHandlerMethods
        handles method_call
        namespace_only
        process { handle_comments }
      end
    end
  end
end
