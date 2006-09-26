class PayloadsController < ApplicationController
  
	def list
		@all_payloads = Payload.get_available()
	end

	def view
		@all_payloads = Payload.get_available()
	end

	def generate
	end
  
end
