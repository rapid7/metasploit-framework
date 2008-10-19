#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Request::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Request

	def test_to_s
		h = Klass.new

		h.headers['Foo']     = 'Fishing'
		h.headers['Chicken'] = 47
		h.auto_cl = true

		assert_equal(
			"GET / HTTP/1.1\r\n" +
			"Foo: Fishing\r\n" +
			"Content-Length: 0\r\n" +
			"Chicken: 47\r\n\r\n", h.to_s)
	end

	def test_from_s
		h = Klass.new

		h.from_s(
			"POST /foo HTTP/1.0\r\n" +
			"Lucifer: Beast\r\n" +
			"HoHo: Satan\r\n" +
			"Eat: Babies\r\n" +
			"\r\n")

		assert_equal('POST', h.method, 'method')
		assert_equal('/foo', h.uri, 'uri')
		assert_equal('1.0', h.proto, 'proto')
		assert_equal('Babies', h['Eat'], 'header')

		assert_equal("POST /foo HTTP/1.0\r\n", h.cmd_string, 'cmd_string')

		h.method = 'GET'
		assert_equal("GET /foo HTTP/1.0\r\n", h.cmd_string, 'set method')

		h.uri = '/bar'
		assert_equal("GET /bar HTTP/1.0\r\n", h.cmd_string, 'set uri')

		h.proto = '1.2'
		assert_equal("GET /bar HTTP/1.2\r\n", h.cmd_string, 'set proto')
	end

	def junk_request
		h = Klass.new
		h.from_s("GET /foo/bar.html HTTP/1.0\r\n" + "Foo: Bar\r\n\r\n")
		return h
	end

	def test_junk_slashes
		srand(0)

		h = junk_request
		assert_equal('GET', h.method, 'method')
		assert_equal('1.0', h.proto, 'proto')
		assert_equal('Bar', h['Foo'], 'header')
		assert_equal('/foo/bar.html', h.uri, 'uri')

		h = junk_request
		h.junk_directories = 1
		assert_equal('/D/../DnJT/../kXG/../Y/../BmnXu/../foo/lZ/../J/../zQzFP/../S/../Yxzd/../bar.html', h.uri, 'junk directories')

		h = junk_request
		h.junk_slashes = 1
		assert_equal('/foo//bar.html', h.uri, 'junk slashes')

		h = junk_request
		h.junk_self_referring_directories = 1
		assert_equal('/././foo/././bar.html', h.uri, 'junk referring directories')

		h = junk_request
		h.junk_param_start = 1
		assert_equal('/%3fgf=XjLyc/../foo/bar.html', h.uri, 'junk start of params')
		
		h = junk_request
		h.junk_end_of_uri = 1
		assert_equal('/%20HTTP/1.0%0d%0a/../../foo/bar.html', h.uri, 'junk end of URI')
	end

	def test_params
		srand(0)

		h = junk_request
		assert_equal('/foo/bar.html', h.uri, 'uri')

		h.uri_parts['QueryString']['B'] = 'a'
		assert_equal('/foo/bar.html?B=a', h.uri, 'uri with param')
		
		h.uri_parts['QueryString']['B'] = ['a','b']
		assert_equal('/foo/bar.html?B=a&B=b', h.uri, 'uri with a param with multiple values')
		
		h.uri_parts['QueryString']['B'] = '='
		assert_equal('/foo/bar.html?B=%3d', h.uri, 'uri with a param that requires escaping')
	
		assert_equal(
    		"GET /foo/bar.html?B=%3d HTTP/1.0\r\n" +
    		"Foo: Bar\r\n" +
    		"Content-Length: 0\r\n" +
			"\r\n", h.to_s, 'GET to_s'
		)
		
		h.method = 'POST'
		assert_equal(
    		"POST /foo/bar.html HTTP/1.0\r\n" +
    		"Foo: Bar\r\n" +
    		"Content-Length: 5\r\n" +
			"\r\n" +
			'B=%3d',
			h.to_s, 'POST to_s'
		)

		h.body = 'FOO'
		assert_equal(
    		"POST /foo/bar.html HTTP/1.0\r\n" +
    		"Foo: Bar\r\n" +
    		"Content-Length: 3\r\n" +
			"\r\n" +
			'FOO',
			h.to_s, 'POST to_s, with hardcoded body'
		)

	end

	def test_junk_params
		srand(0)
		h = junk_request
		
		h.junk_params = 1
		h.uri_parts['QueryString']['a'] = 'b'
		h.uri_parts['QueryString']['c'] = 'd'

		assert_equal("GET /foo/bar.html?eZUhlXbdhzzW=HpxJATk&UwDqBU=EQwvK&oebrfUGJbvjTMSxKih=MkBx&nYkjF=DiohcEa&tzJFh=eIUHDVbs&a=b&UHTfAFbreJT=VlcIruAo&mZKziXgT=z&hsytpEdbRjC=tPkpE&yNetXi=JaaW&PiazmuQvoAKLNHeGt=ePpmrS&c=d&BpCycOlbkfdyudyhMgpQCIzKwabBAFYiP=ulrTYGUG&zGCccmlFtJkNVfRjtzIZVtlWQZulBFGMa=OIHtFvqDKybZDOS&ERFeYDFokx=YhShOxHruwhRdMugizXZuyrpuAMJSEHDwMltwtSzxHaxudDKUqBUQqycaXwC&JCspZkaEpKM=hlnghajZyYSUecISZYnqcYSDsTtAKDGbjGTiyymUrAktp&hMPhXMF=BKGGmmLyVyyzCMdJzIFrBrPMvMVSZNecspVGkwoaeFP HTTP/1.0\r\nFoo: Bar\r\nContent-Length: 0\r\n\r\n", h.to_s, 'junk params (GET)')

		h.method = 'POST'
		assert_equal("POST /foo/bar.html HTTP/1.0\r\nFoo: Bar\r\nContent-Length: 591\r\n\r\nxfgwQgKMdA=WTFkTkFc&axTMmHQdAXPKDDQwJ=lwRJs&PmOhEQkHXbuHWieQbvv=LXO&eaiRjHtwlENl=rIgR&kBdFQmoWeT=UqKDW&a=b&dpoRzoqedheulYQ=ndBX&AXlvaZZGYPlpR=w&uFTvWtLLhHawHvgk=XVC&KFmmkBkFFmjYx=yJExY&CTDNLNkRaGviVUqRlZV=kEviLihu&c=d&LhZhftGZYtmzQXaDaudCF=HPOjnHzmzdxLDNYEzWdmLOSZsDlHdOLJLQnBScAVYJISLczRPDqYVcVOvBMLZn&atiBQBQhhsmoINqT=gXEfWAlfPTPzMtKpQGVeDQABygrSSWPPcHbYYMNSOOUHsrbsPXLNdfu&EcBxxXQpawCvRUmAGsWPKio=VigqsjpnbwKERDleXdmeLCdHzJXAwRozVeaPwRKRDnJ&DHQiEakGgRlbzOWfIdcfiRcvQIsHMgUrLd=AUtcNlvnyEuMlwEpkQSleujwAxJyhwxMGzkjmkeyTmsjO&zRDdbDhzbkVnqKdxdYyQAkiNBCCTMenVNx=zMxABkKqgcCcBNTvRkHGJPSdqSCdRjT",h.to_s, 'junk params (POST)')

		h.method = 'SEARCH'
		assert_equal("SEARCH /foo/bar.html HTTP/1.0\r\nFoo: Bar\r\nContent-Length: 522\r\n\r\nMjtCUDRsmqKl=vbEzWljeH&YvPKTNnlnSHYg=ovkqQaoQ&geUXPsTibtiRXbNwXeF=nhxicBEVIy&jwjZFB=HBBH&kNsybgrTitkQwq=rDITuAUgir&a=b&YCHsLzcfBQ=SOV&vFhqCboTPHsdjhwxQYFz=RtgW&mJFMqQ=EZ&tRdGcKFkkUyyWKreOzw=BoHFPpgXO&dzZEAaU=YREgxR&c=d&kfeJswjgOXgcrh=usIlCRPDVwydlWSHxaEtZazvTOSgbkmUsDSNzxfhSMvbniHetQBYQtb&yYwMEwzuoO=KbOmNEWPdOqZLfbWurUCZAfuGSWuZNMlTfcTooZvdcqKURAnmiBwWt&xWncBVCgyGmjkXzSmZuPxbVBJzRLADk=TvFUEpQQFgWDIcpKmcfsLibxH&mFJYMohOtPEW=CHtIFnPPpZWZZTdJLjanSIBjyxuKKYfrbNOFXqnxlmLrYRVeSZdlxoxqf&LOgBBkZMIyMY=DKHcOIujjRXMtHvuneTqtyBr", h.to_s, 'junk params (SEARCH)')
	end

	def test_junk_pipelining
		srand(0)

		h = Klass.new
		h.from_s("GET /foo HTTP/1.0\r\n" + "Foo: Bar\r\n\r\n")
		h.junk_pipeline = 1
		assert_equal("GET / HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\nGET /foo HTTP/1.0\r\nFoo: Bar\r\nContent-Length: 0\r\nConnection: Closed\r\n\r\n", h.to_s, 'pipeline')
	end

	def test_junk_all
        srand(0)

        h = junk_request
        h.junk_slashes = 1
        h.junk_directories = 1
        h.junk_self_referring_directories = 1
		h.junk_end_of_uri = 1
		h.junk_param_start = 1

        seen = {}
		expect = [
			{"//"=>145, "/./"=>35, "param"=>1, "http"=>1, "/w/../"=>3},
			{"//"=>149, "/./"=>35, "param"=>1, "http"=>1, "/w/../"=>3},
			{"//"=>130, "/./"=>30, "param"=>1, "http"=>1, "/w/../"=>2},
			{"//"=>165, "/./"=>40, "param"=>1, "http"=>1, "/w/../"=>4},
			{"//"=>145, "/./"=>35, "param"=>1, "http"=>1, "/w/../"=>3},
		]
		i = 0
        5.times {
            str = h.uri.dup
            assert_not_equal('/foo/bar.html', str, 'all the junk')
            assert_nil(seen[str], 'all the junk, not a dup rand')
            seen[str] = 1

			seen = { '/./' => 0, '//' => 0, '/w/../' => 0, 'http' => 0, 'param' => 0}
			matched = 1
			while matched == 1
				# p str
				if str.sub!(/\/%20HTTP\/1.0%0d%0a\/\.\.\/\.\.\//, '/')
					seen['http'] += 1;
				elsif str.sub!(/\/%3f\w+=\w+\/\.\.\//i, '/')
					seen['param'] += 1;
				elsif str.sub!(/\/\w+\/\.\.\//, '/')
					seen['/./'] += 1;
				elsif str.sub!(/\/\//, '/')
					seen['//'] += 1;
				elsif str.sub!(/\/.\//, '/')
					seen['/w/../'] += 1;
				else
					matched = 0
				end
			end

			assert_equal('/foo/bar.html', str, 'normalized')
			assert_equal(expect[i], seen, 'expected counts')
			i += 1
        }
    end

	def test_normalize
		h = junk_request
		h.uri = '/foo/..////./././asdf/././//../bar.html'
		assert_equal('/bar.html', h.uri, 'normalize on set')
	end
end