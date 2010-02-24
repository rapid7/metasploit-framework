
module Rex
module Script
class Shell

	attr_accessor :client, :framework, :path, :error, :args
	attr_accessor :session

	def initialize(client, path)
		self.client    = client
		self.framework = client.framework
		self.path      = path

		# Convenience aliases
		self.session   = self.client
	end

	def completed
		raise Rex::Script::Completed
	end

	def run(*argset)
		args = argset.join(" ")
		self.args = args
		begin
			eval(::File.read(self.path, ::File.size(self.path)), binding )
		rescue ::Interrupt
		rescue ::Rex::Script::Completed
		rescue ::Exception => e
			self.error = e
			raise e
		end
	end

	def print(*args);         client.user_output.print(*args);          end
	def print_status(*args);  client.user_output.print_status(*args);   end
	def print_error(*args);   client.user_output.print_error(*args);    end
	def print_good(*args);    client.user_output.print_good(*args);     end
	def print_line(*args);    client.user_output.print_line(*args);     end

end
end
end
