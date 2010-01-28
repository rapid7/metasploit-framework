#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/drda/packet'

class Rex::Proto::DRDA::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::DRDA
	Konst = Rex::Proto::DRDA::Constants

	# Test a sample param
	def test_mgrlvlls_param
		p = Klass::MGRLVLLS_PARAM.new
		assert_kind_of(Struct, p)
		assert_equal(Konst::MGRLVLLS, p.codepoint)
	end

	# Test a sample ddm
	def test_secchk_ddm
		d = Klass::SECCHK_DDM.new
		assert_kind_of Struct, d
		assert_equal Konst::SECCHK, d.codepoint
	end

	# All parameter names should have a corresponding codepoint, 
	# except "DDM_PARAM" (a generic parameter).
	def test_all_param_codepoints
		params = Klass.constants.map {|x| x if x =~ /PARAM$/}.compact
		assert_operator params.size, :>=, 6 # Allow for more later.
		params.each do |p|
			cp = p.split(/_PARAM/).first
			next if cp == "DDM"
			assert Konst.const_defined? cp
			assert_kind_of Numeric, Konst.const_get(cp)
		end
	end

	# Similarly, so should DDM Structs.
	def test_all_ddm_codepoints
		ddms = Klass.constants.map {|x| x if x =~ /DDM$/}.compact
		assert_operator ddms.size, :>=, 4 # Allow for more later.
		ddms.each do |p|
			cp = p.split(/_DDM/).first
			next if cp == "BASIC"
			assert_kind_of Numeric, Konst.const_get(cp)
		end
	end

	# Ensure that all params have the same struct.
	def test_param_struct
		params = Klass.constants.map {|x| x if x =~ /PARAM$/}.compact
		params.each do |p|
			obj = Klass.const_get(p).new
			assert_equal 3, obj.size
			assert_respond_to obj, :codepoint
			assert_respond_to obj, :length
			assert_respond_to obj, :payload
		end
	end

	# Make some similiar assertions about DDMs, though specific DDMs
	# will have particular elements after the codepoint, usually more
	# than one.
	def test_ddm_struct
		ddms = Klass.constants.map {|x| x if x =~ /DDM$/}.compact
		ddms.each do |d|
			obj = Klass.const_get(d).new
			assert_operator obj.size, :>=, 7 
			assert_respond_to obj, :length
			assert_respond_to obj, :magic
			assert_respond_to obj, :format
			assert_respond_to obj, :correlid
			assert_respond_to obj, :length2
			assert_respond_to obj, :codepoint
		end
	end

	# The server packet is special since it's an Array of BASIC_DDM's,
	# and doesn't have a particular, fixed struct. (It would be nice
	# to build those up on the fly, but we're not really interested in
	# validating most server responses right now.
	def test_server_packet_structure
		s = Klass::SERVER_PACKET.new
		assert_kind_of Array, s
		assert_respond_to s, :to_s
		assert_respond_to s, :sz
		assert_respond_to s, :read
	end

	# Exercise the SERVER_PACKET#read function with a sample packet.
	def test_server_packet_read
		pkt = "0015d0420001000f1219000611490000000511a4000050d0520002004a2201000611490000000c112ee2d8d3f0f8f0f2f4000d002fd8e3c4e2d8d3e7f8f6000a00350006119c033300062103022e00172135c3f0c1f8f6c1f0f14bc5c6f1f2070402195612008cd0030002008624080000000000303030303053514c303830323400ffffffff0200000000000000030000000000000000000000202020202020202020202000124d59444232444220202020202020202020200000003331ff383139ff4d59555345522020ff4d594442324442ff514442322f4c494e5558ff353538ff353538ff30ff31323038ff30ffff".scan(/../).map {|x| x.to_i(16).chr}.join
		s = Klass::SERVER_PACKET.new
		assert_equal 0, s.size
		s.read(pkt)
		assert_equal 3, s.size
		assert_equal Konst::SECCHKRM, s[0].codepoint
		assert_equal Konst::ACCRDBRM, s[1].codepoint
		assert_equal Konst::SQLCARD, s[2].codepoint
		assert_equal 0xd0, s[0].magic 
		assert_equal 0x52, s[1].format
		assert_equal 134, s[2].length2
		assert_equal 21+80+140, s.sz
	end

end

