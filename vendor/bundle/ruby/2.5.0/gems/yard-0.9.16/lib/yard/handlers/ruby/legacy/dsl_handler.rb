# frozen_string_literal: true
module YARD
  module Handlers
    module Ruby
      module Legacy
        # (see Ruby::DSLHandler)
        class DSLHandler < Base
          include CodeObjects
          include DSLHandlerMethods
          handles TkIDENTIFIER
          namespace_only
          process { handle_comments }
        end
      end
    end
  end
end
