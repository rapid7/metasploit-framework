module Msf
class PersistentStorage

###
#
# This class persists the state of the framework to a flatfile in a human
# readable format.  At the moment, the level of information it conveys is
# rather basic and ugly, but this is just a prototype, so it will be improved.
# Oh yes, it will be improved.
#
###
class Flatfile < PersistentStorage

	#
	# Initializes the flatfile for storage based on the parameters specified.
	# The hash must contain a FilePath attribute.
	#
	def initialize(*params)
		raise ArgumentError, "You must specify a file path" if (params.length == 0)

		self.path = params[0]
	end

	#
	# This method stores the current state of the framework in human readable
	# form to a flatfile.  This can be used as a reporting mechanism.
	#
	def store(framework)
		# Open the supplied file path for writing.
		self.fd = File.new(self.path, "w")

		begin
			store_general(framework)
			store_recon(framework)
		ensure
			self.fd.close
		end
	end

protected

	attr_accessor :fd, :path # :nodoc:

	#
	# This method stores general information about the current state of the
	# framework instance.
	#
	def store_general(framework)
		fd.print(
			"\n" +
			"Metasploit Framework Report\n" +
			"===========================\n\n" +
			"Generated: #{Time.now}\n\n")
	end

	#
	# This method stores the recon information that has been collected by this
	# framework instance.
	#
	def store_recon(framework)
		fd.print(
			"Reconnaissance Information\n" +
			"==========================\n\n")

		framework.reconmgr.each_host { |address, host|
			store_recon_host(framework, host)
		}
	end

	#
	# This method stores information about a specific host and its services.
	#
	def store_recon_host(framework, host)
		fd.print(
			"Host: #{host.address}\n")

		store_recon_host_services(framework, host)

		fd.print("\n")
	end

	#
	# This method stores information about the services running on a host, if
	# any.
	#
	def store_recon_host_services(framework, host)
		host.services.entities.each { |name, proto|
			if (proto.kind_of?(Msf::Recon::Entity::Group) == true)
				proto.entities.each { |name, serv|
					fd.print(
						"\tService: #{serv.port} (#{serv.proto})\n")
				}
			end
		}
	end

	Msf::PersistentStorage.add_storage_class('flatfile', self)

end

end
end
