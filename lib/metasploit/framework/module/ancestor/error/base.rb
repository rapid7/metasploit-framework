# Base error class for all errors raised by
# by {Metasploit::Framework::Module::Ancestor::Namespace}.
class Metasploit::Framework::Module::Ancestor::Error::Base < Metasploit::Framework::Error
	def initialize(attributes={})
		@module_path = attributes[:module_path]
		@module_reference_name = attributes[:module_reference_name]

		message_parts = []
		message_parts << "Failed to load module"

		if module_reference_name or module_path
			clause_parts = []

			if module_reference_name
				clause_parts << module_reference_name
			end

			if module_path
				clause_parts << "from #{module_path}"
			end

			clause = clause_parts.join(' ')
			message_parts << "(#{clause})"
		end

		causal_message = attributes[:causal_message]

		if causal_message
			message_parts << "due to #{causal_message}"
		end

		message = message_parts.join(' ')

		super(message)
	end

	attr_reader :module_reference_name
	attr_reader :module_path
end