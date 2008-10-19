#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/exploitation/opcodedb'
require 'rex/socket'

class Rex::Exploitation::OpcodeDb::UnitTest < Test::Unit::TestCase

	Klass = Rex::Exploitation::OpcodeDb::Client
	SrvPort = 60000

	def test_meta_types
		srv_cli

		begin
			proc_req_resp(%q{<Array><Hash><Entry name="id">1</Entry><Entry name="name">foo</Entry></Hash><Hash><Entry name="id">2</Entry><Entry name="name">dog</Entry></Hash></Array>})

			mt = @r.meta_types

			assert_kind_of(Array, mt)
			assert_equal(2, mt.length)
			assert_equal(1, mt[0].id)
			assert_equal("foo", mt[0].name)
			assert_equal(2, mt[1].id)
			assert_equal("dog", mt[1].name)
		ensure
			@s.close
		end
	end

	def test_groups
		srv_cli

		begin
			proc_req_resp(%q{<Array><Hash><Entry name="id">47</Entry><Entry name="name">foo</Entry></Hash><Hash><Entry name="id">2</Entry><Entry name="name">dog</Entry></Hash></Array>})

			mt = @r.groups

			assert_kind_of(Array, mt)
			assert_equal(2, mt.length)
			assert_equal(47, mt[0].id)
			assert_equal("foo", mt[0].name)
			assert_equal(2, mt[1].id)
			assert_equal("dog", mt[1].name)
		ensure
			@s.close
		end
	end

	def test_platforms
		srv_cli
		
		begin
			proc_req_resp(%q{<Array><Hash><Entry name="id">12</Entry><Entry name="name">Windows XP SP2</Entry><Entry name="desc">Windows Coolness</Entry><Entry name="maj_ver">5</Entry><Entry name="min_ver">1</Entry><Entry name="maj_patch_level">2</Entry><Entry name="min_patch_level">0</Entry><Entry name="modules">10</Entry></Hash></Array>})

			osv = @r.platforms

			assert_kind_of(Array, osv)
			assert_equal(1, osv.length)
			assert_equal(12, osv[0].id)
			assert_equal("Windows XP SP2", osv[0].name)
			assert_equal("Windows Coolness", osv[0].desc)
			assert_equal(5, osv[0].maj_ver)
			assert_equal(1, osv[0].min_ver)
			assert_equal(2, osv[0].maj_patch_level)
			assert_equal(0, osv[0].min_patch_level)
			assert_equal(10, osv[0].modules)
		ensure
			@s.close
		end
	end

	def test_modules
		srv_cli

		begin
			proc_req_resp(%q{<Array><Hash>
				<Entry name="id">1</Entry>
				<Entry name="name">kernel32.dll</Entry>
				<Entry name="locale">
					<Hash>
						<Entry name="id">4</Entry>
						<Entry name="name">English</Entry>
					</Hash>
				</Entry>
				<Entry name="maj_maj_ver">4</Entry>
				<Entry name="maj_min_ver">100</Entry>
				<Entry name="min_maj_ver">2</Entry>
				<Entry name="min_min_ver">7</Entry>
				<Entry name="timestamp">403242822</Entry>
				<Entry name="base_address">100000000</Entry>
				<Entry name="image_size">40000</Entry>
				<Entry name="segments">
					<Array>
						<Hash>
							<Entry name="type">text</Entry>
							<Entry name="base_address">3228094</Entry>
							<Entry name="segment_size">4000</Entry>
							<Entry name="writable">true</Entry>
							<Entry name="readable">true</Entry>
							<Entry name="executable">false</Entry>
						</Hash>
					</Array>
				</Entry>
				<Entry name="imports">
					<Array>
						<Hash>
							<Entry name="name">FoolFunction</Entry>
							<Entry name="address">3242344</Entry>
							<Entry name="ordinal">5</Entry>
						</Hash>
					</Array>
				</Entry>
				<Entry name="exports">
					<Array>
						<Hash>
							<Entry name="name">FoolFunctionExport</Entry>
							<Entry name="address">32423445</Entry>
							<Entry name="ordinal">51</Entry>
						</Hash>
					</Array>
				</Entry>
				</Hash></Array>})

			m = @r.modules

			assert_kind_of(Array, m)
			assert_equal(1, m[0].id)
			assert_equal("kernel32.dll", m[0].name)
			assert_equal(4, m[0].locale.id)
			assert_equal("English", m[0].locale.name)
			assert_equal(4, m[0].maj_maj_ver)
			assert_equal(100, m[0].maj_min_ver)
			assert_equal(2, m[0].min_maj_ver)
			assert_equal(7, m[0].min_min_ver)
			assert_equal(403242822, m[0].timestamp.to_i)
			assert_equal(100000000, m[0].base_address)
			assert_equal(40000, m[0].image_size)
			assert_kind_of(Array, m[0].segments)
			assert_equal("text", m[0].segments[0].type)
			assert_equal(3228094, m[0].segments[0].base_address)
			assert_equal(4000, m[0].segments[0].size)
			assert_equal(true, m[0].segments[0].writable)
			assert_equal(true, m[0].segments[0].readable)
			assert_equal(false, m[0].segments[0].executable)
			assert_kind_of(Array, m[0].imports)
			assert_equal("FoolFunction", m[0].imports[0].name)
			assert_equal(3242344, m[0].imports[0].address)
			assert_equal(5, m[0].imports[0].ordinal)
			assert_kind_of(Array, m[0].exports)
			assert_equal("FoolFunctionExport", m[0].exports[0].name)
			assert_equal(32423445, m[0].exports[0].address)
			assert_equal(51, m[0].exports[0].ordinal)
		ensure
			@s.close
		end
	end

	def test_locales
		srv_cli

		begin
			proc_req_resp(%q{<Array><Hash>
				<Entry name="id">4</Entry>
				<Entry name="name">English</Entry>
			</Hash>
			<Hash>
				<Entry name="id">5</Entry>
				<Entry name="name">French</Entry>
			</Hash></Array>})
		
			l = @r.locales

			assert_kind_of(Array, l)
			assert_equal(2, l.length)
			assert_equal(4, l[0].id)
			assert_equal("English", l[0].name)
			assert_equal(5, l[1].id)
			assert_equal("French", l[1].name)
		ensure
			@s.close
		end
	end

	def test_search
		srv_cli

		begin
			proc_req_resp(%q{
				<Array>
					<Hash>
						<Entry name="id">400</Entry>
						<Entry name="address">34242324</Entry>
						<Entry name="type">
							<Hash>
								<Entry name="id">4</Entry>
								<Entry name="name">jmp esp</Entry>
						<Entry name="group">
							<Hash>
								<Entry name="id">40</Entry>
								<Entry name="name">reg</Entry>
							</Hash>
						</Entry>
							</Hash>
						</Entry>
					</Hash>
				</Array>})

			o = @r.search

			assert_kind_of(Array, o)
			assert_equal(1, o.length)
			assert_equal(400, o[0].id)
			assert_equal(34242324, o[0].address)
			assert_equal(4, o[0].type.id)
			assert_equal("jmp esp", o[0].type.name)
			assert_equal(40, o[0].group.id)
			assert_equal("reg", o[0].group.name)
		ensure
			@s.close
		end
	end

	def test_statistics
		srv_cli

		begin
			proc_req_resp(%q{
				<Hash>
					<Entry name="modules">40</Entry>
					<Entry name="opcodes">50</Entry>
					<Entry name="opcode_types">60</Entry>
					<Entry name="platforms">70</Entry>
					<Entry name="architectures">80</Entry>
					<Entry name="module_segments">90</Entry>
					<Entry name="module_imports">100</Entry>
					<Entry name="module_exports">110</Entry>
					<Entry name="last_update">120</Entry>
				</Hash>
				})

			s = @r.statistics

			assert_equal(40, s.modules)
			assert_equal(50, s.opcodes)
			assert_equal(60, s.opcode_types)
			assert_equal(70, s.platforms)
			assert_equal(80, s.architectures)
			assert_equal(90, s.module_segments)
			assert_equal(100, s.module_imports)
			assert_equal(110, s.module_exports)
			assert_equal(120, s.last_update.to_i)
		ensure
			@s.close
		end
	end

protected

	def srv_cli
		@r = Klass.new('127.0.0.1', SrvPort)
		@s = Rex::Socket::TcpServer.create(
			'LocalHost' => '127.0.0.1',
			'LocalPort' => SrvPort)
	end

	def proc_req_resp(buf)
		thr = Thread.new {
			cli = @s.accept
			@buffer = cli.get

			cli.put("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n#{buf}")
			cli.close
		}
	end

end