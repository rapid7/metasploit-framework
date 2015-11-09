#!/usr/bin/ruby

base = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(base)))

require 'test/unit'
require 'kissfft'
require 'pp'

#
# Simple unit test
#

class KissFFT::UnitTest < Test::Unit::TestCase
	def test_version
		assert_equal(String, KissFFT.version.class)
		puts "KissFFT version: #{KissFFT.version}"
	end		
	def test_fftr
		data = File.read('sample.data').unpack('s*')
		
		min = 1
		res = KissFFT.fftr(8192, 8000, 1, data)

		tones = {}
		res.each do |x|
			rank = x.sort{|a,b| a[1].to_i <=> b[1].to_i }.reverse
			rank[0..10].each do |t|
				f = t[0].round
				p = t[1].round
				next if f == 0
				next if p < min
				tones[ f ] ||= []
				tones[ f ] << t
			end
		end

		tones.keys.sort.each do |t|
			next if tones[t].length < 2
			puts "#{t}hz"
			tones[t].each do |x|
				puts "\t#{x[0]}hz @ #{x[1]}"
			end
		end

	end					
end
