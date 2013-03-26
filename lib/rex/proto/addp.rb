# -*- coding: binary -*-
module Rex
module Proto

	#
	# This provides constants, encoding, and decoding routines for Digi International's ADDP protocol
	#
	class ADDP

		require "rex/socket"

		#
		# See the following URLs for more information:
		# - http://qbeukes.blogspot.com/2009/11/advanced-digi-discovery-protocol_21.html
		# - http://www.digi.com/wiki/developer/index.php/Advanced_Device_Discovery_Protocol_%28ADDP%29
		#


		MAGICS          = %W{ DIGI DVKT DGDP }
		ERRORS          = %W{ no_response unknown success authenticaton_failed unit_has_address invalid_value invalid_data unsupported_command }
		WLAN_ENC_MODES  = %W{ unknown none wep40 wep128 }
		WLAN_AUTH_MODES = %W{ unknown open shared_key open_shared_key }
		HWTYPES         = %W{
			unknown ps3_desk8 ps3_desk16 ps3_desk32 ps3_rack16 ps2_desk16 ps2_rack16
			lets_desk1 lets_desk2 lets_desk4 dorpia_dinrail1 nubox01 nubox02 nubox04
			digione_sp digione_ia digione_em
		}

		CMD_CONF_REQ             = 1
		CMD_CONF_REP             = 2
		CMD_SET_ADDR_REQ         = 3
		CMD_SET_ADDR_REP         = 4
		CMD_REBOOT_REQ           = 5
		CMD_REBOOT_REP           = 6
		CMD_SET_DHCP_REQ         = 7
		CMD_SET_DHCP_REP         = 8
		CMD_SET_WL_REQ           = 9
		CMD_SET_WL_REP           = 10
		CMD_SET_WL_COUNTRIES_REQ = 11
		CMD_SET_WL_COUNTRIES_REP = 12
		CMD_EDP                  = 13
		CMD_CNT                  = 14


		def self.encode_password(pwd="dbps")
			[pwd.length].pack("C") + pwd
		end

		def self.request_config(magic, dmac="\xff\xff\xff\xff\xff\xff")
			mac = (dmac.length == 6) ? dmac : Rex::Socket.eth_aton(dmac)
			req = magic + [ CMD_CONF_REQ, 6].pack("nn") + mac
			return req
		end

		def self.request_config_all(dmac="\xff\xff\xff\xff\xff\xff")
			mac = (dmac.length == 6) ? dmac : Rex::Socket.eth_aton(dmac)
			res = []
			MAGICS.each { |m| res << self.request_config(m, dmac) }
			return res
		end

		def self.request_static_ip(magic, dmac, ip, mask, gw, pwd="dbps")
			mac = (dmac.length == 6) ? dmac : Rex::Socket.eth_aton(dmac)
			buf =
				Rex::Socket.addr_aton(ip) +
				Rex::Socket.addr_aton(mask) +
				Rex::Socket.addr_aton(gw) +
				mac +
				self.encode_password(pwd)

			req = magic + [CMD_SET_ADDR_REQ, buf.length].pack("nn") + buf
			return req
		end

		def self.request_dhcp(magic, dmac, enabled, pwd="dbps")
			mac = (dmac.length == 6) ? dmac : Rex::Socket.eth_aton(dmac)
			buf =
				[ enabled ? 1 : 0 ].pack("C") +
				mac +
				self.encode_password(pwd)

			req = magic + [CMD_SET_DHCP_REQ, buf.length].pack("nn") + buf
			return req
		end

		def self.request_reboot(magic, dmac, pwd="dbps")
			mac = (dmac.length == 6) ? dmac : Rex::Socket.eth_aton(dmac)
			buf =
				mac +
				self.encode_password(pwd)

			req = magic + [CMD_REBOOT_REQ, buf.length].pack("nn") + buf
			return req
		end

		def self.decode_reply(data)
			res = {}
			r_magic = data[0,4]
			r_ptype = data[4,2].unpack("n").first
			r_plen  = data[6,2].unpack("n").first
			buff    = data[8, r_plen]
			bidx    = 0

			res[:magic] = data[0,4]
			res[:cmd]   = r_ptype

			while bidx < (buff.length - 2)
				i_type, i_len = buff[bidx, 2].unpack("CC")
				i_data        = buff[bidx + 2, i_len]

				break if i_data.length != i_len

				case i_type
				when 0x01
					res[:mac]  = Rex::Socket.eth_ntoa(i_data)
				when 0x02
					res[:ip]   = Rex::Socket.addr_ntoa(i_data)
				when 0x03
					res[:mask] = Rex::Socket.addr_ntoa(i_data)
				when 0x04
					res[:hostname] = i_data
				when 0x05
					res[:domain] = i_data
				when 0x06
					res[:hwtype] = HWTYPES[ i_data.unpack("C").first ] || HWTYPES[ 0 ]
				when 0x07
					res[:hwrev] = i_data.unpack("C").first
				when 0x08
					res[:fwrev] = i_data
				when 0x09
					res[:msg] = i_data
				when 0x0a
					res[:result] = i_data.unpack("C").first
				when 0x0b
					res[:gw]   = Rex::Socket.addr_ntoa(i_data)
				when 0x0c
					res[:advisory]  = i_data.unpack("n").first
				when 0x0d
					res[:hwname] = i_data
				when 0x0e
					res[:realport] = i_data.unpack("N").first
				when 0x0f
					res[:dns] = Rex::Socket.addr_ntoa(i_data)
				when 0x10
					res[:dhcp] = (i_data.unpack("C").first == 0) ? false : true
				when 0x11
					res[:error] = ERRORS[ i_data.unpack("C").first ] || ERRORS[0]
				when 0x12
					res[:ports] = i_data.unpack("C").first
				when 0x13
					res[:realport_enc] = (i_data.unpack("C").first == 0) ? false : true
				when 0x14
					res[:version] = i_data.unpack("n").first
				when 0x15
					res[:vendor_guid] = i_data.unpack("H*") # GUID
				when 0x16
					res[:iftype] = i_data.unpack("C").first
				when 0x17
					res[:challenge] = i_data # Unknown format
				when 0x18
					res[:cap_port] = i_data.unpack("n").first
				when 0x19
					res[:edp_devid] = i_data.unpack("H*").first # Unknown format
				when 0x1a
					res[:edp_enabled] = (i_data.unpack("C").first == 0) ? false : true
				when 0x1b
					res[:edp_url] = i_data
				when 0x1c
					res[:wl_ssid] = i_data
				when 0x1d
					res[:wl_auto_ssid] = (i_data.unpack("n").first == 0) ? false : true
				when 0x1e
					res[:wl_tx_enh_power] = i_data.unpack("n").first
				when 0x1f
					res[:wl_auth_mode] = WLAN_AUTH_MODES[ i_data.unpack("n").first ] || WLAN_AUTH_MODES[ 0 ]
				when 0x20
					res[:wl_enc_mode] = WLAN_ENC_MODES[ i_data.unpack("n").first ] || WLAN_ENC_MODES[ 0 ]
				when 0x21
					res[:wl_enc_key] = i_data
				when 0x22
					res[:wl_cur_country] = i_data
				when 0x23
					res[:wl_country_list] = i_data
				else
					# Store unknown responses
					res["unknown_0x#{"%.2x" % i_type}".to_sym] = i_data
				end

				bidx = bidx + 2 + i_len
			end
			return res
		end

		def self.reply_to_string(res)
			str = ""

			fields = [
				:hwname, :hwtype, :hwrev, :fwrev,
				:mac, :ip, :mask, :gw, :hostname, :domain, :dns, :dhcp,
				:msg, :result, :error,
				:advisory, :ports, :realport, :realport_enc,
				:version, :vendor_guid, :iftype, :challenge, :cap_port, :edp_devid, :edp_enabled,
				:edp_url, :wl_ssid, :wl_auto_ssid, :wl_tx_enh_power, :wl_auth_mode, :wl_enc_mode,
				:wl_enc_key, :wl_cur_country, :wl_country_list, :magic
			]

			fields.each do |fname|
				next unless res.has_key?(fname)
				str << "#{fname}:#{res[fname]} "
			end
			return str
		end

	end

end
end

