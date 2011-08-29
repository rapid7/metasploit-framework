require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers
class FogDriver < VmDriver

	def initialize(config,fog_config)
		
		super(config)
		@fog_config = fog_config

		puts "Fog Config: #{fog_config}"

		# Soft dependency
		begin
			require 'fog'
		rescue LoadError
			raise "WARNING: Library fog not found. Could Not Create Driver"
		end

		if @fog_config['fog_type'] == "ec2"

			# AWS / EC2 Base Credential Configuration
			@aws_cert_file = IO.read(fog_config['fog_aws_cert_file']).chomp if fog_config['fog_aws_cert_file']
			@aws_private_key_file = IO.read(fog_config['fog_aws_private_key_file']).chomp if fog_config['fog_aws_private_key_file']
			@ec2_access_key_file = IO.read(fog_config['fog_ec2_access_key_file']).chomp if fog_config['fog_ec2_access_key_file']
			@ec2_secret_access_key_file = IO.read(fog_config['fog_ec2_secret_access_key_file']).chomp if fog_config['fog_ec2_secret_access_key_file']
			
			# Instance Keys
			@ec2_instance_public_key_file = IO.read(fog_config['fog_ec2_instance_public_key_file']).chomp if fog_config['fog_ec2_instance_public_key_file']
			@ec2_instance_private_key_file = IO.read(fog_config['fog_ec2_instance_private_key_file']).chomp if fog_config['fog_ec2_instance_private_key_file']
			
			# Instance Details
			@ec2_base_ami = fog_config['fog_ec2_base_ami']
			@ec2_flavor = fog_config['fog_ec2_flavor']
			@ec2_user = fog_config['fog_ec2_user']
			@ec2_region = fog_config['fog_ec2_region']
					
			# Set up a connection
			@compute = Fog::Compute.new(
				:provider => "Aws",
				:aws_access_key_id => @aws_access_key_file,
				:aws_secret_access_key => @aws_secret_access_key_file )
		else
			raise "Unsupported Fog Type"
		end
	end

	def start
		ec2_settings = {
			:image_id => @ec2_base_ami, 
			:flavor_id =>  @ec2_flavor,
			:public_key_path => @ec2_instance_public_key_file,
			:private_key_path => @ec2_instance_private_key_file,
			:username => @ec2_user}
			
		begin
			@fog_server = @compute.servers.bootstrap(ec2_settings)
		rescue Fog::Compute::AWS::Error => e
			raise "Couldn't authenticate to AWS - did you place keys in the creds/ directory?"
			exit
		end
	end

	def stop
		@fog_server.destroy
	end

	def suspend
		raise "unimplemented"
	end

	def pause
		raise "unimplemented"
	end

	def reset
		raise "unimplemented"
	end

	def create_snapshot(snapshot)
		raise "unimplemented"
	end

	def revert_snapshot(snapshot)
		raise "unimplemented"
	end

	def delete_snapshot(snapshot)
		raise "unimplemented"
	end

=begin

	def run_command(command)
		## vm_driver will need a little patching for this to work, as 
		## amis use keys for auth. i think it's just a matter of not passing the 
		## password to ssh_exec. So maybe the thing to do is have a ssh_key_exec
		## function in vm_driver.rb that does the right thing. 

		script_rand_name = rand(10000)

		if @os == "windows"
			local_tempfile_path = "/tmp/lab_script_#{script_rand_name}.bat"
			remote_tempfile_path = "C:\\\\lab_script_#{script_rand_name}.bat"
			remote_run_command = remote_tempfile_path
		else
			local_tempfile_path = "/tmp/lab_script_#{script_rand_name}.sh"
			remote_tempfile_path = "/tmp/lab_script_#{script_rand_name}.sh"
			remote_run_command = "/bin/sh #{remote_tempfile_path}"
		end

		# write out our script locally
		File.open(local_tempfile_path, 'w') {|f| f.write(command) }

		# since we can't copy easily w/o tools, let's just run it directly :/
		if @os == "linux"
			output_file = "/tmp/lab_command_output_#{rand(1000000)}"
			
			scp_to(local_tempfile_path, remote_tempfile_path)
			ssh_exec(remote_run_command + "> #{output_file}")
			scp_from(output_file, output_file)
			ssh_exec("rm #{output_file}")
			ssh_exec("rm #{remote_tempfile_path}")
			
			# Ghettohack!
			string = File.open(output_file,"r").read
			`rm #{output_file}`
			
		else
			raise "zomgwtfbbqnotools"
		end
	end
	
	def copy_from(from, to)
		raise "unimplemented"
	end

	def copy_to(from, to)
		raise "unimplemented"
	end

	def check_file_exists(file)
		raise "unimplemented"
	end

	def create_directory(directory)
		raise "unimplemented"
	end
=end

	def cleanup
		@fog_server.destroy
	end

	def running?
		return true #TODO
	end

end
end 
end
