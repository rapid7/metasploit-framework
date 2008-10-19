#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Packet::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Packet

	def test_junk_headers
		srand(0)
		h = Klass.new
		h.headers.cmd_string = "GET / HTTP/1.0\r\n"
		h.headers['TestMe'] = 'bob'
		h.headers.junk_headers = 1
		expected = "GET / HTTP/1.0\r\nX-v1AD7DnJTVykXGYYM: BmnXuYRlZNIJUzQzFPvASjYxzdTTOngBJ5gfK0XjLy3ciAAk1Fmo0RPEpq6f4BBnp5jm3LuSbAOj1M5qULEGEv0DMk0oOPUj6XPN1VwxFpjAfFeAxykiwdDiqNwnVJAKyr6X7C5ije7DSujURybOp6BkKWroLCzQg2AmTuqz48oNeY9CDeirNwoITfIaC40Ds9OgEDtL8WN5tL4QYdVuZQ85219Thogk775GVfNH4YPpSo2PLmvd5Bf2sY9YDSvDqMmjW9FXrgLoUK2rl9cvoCbTZX1zuU1dDjnJJpXDuaysDfJKbtHn9VhsiiY\r\nX-FokALi: 1QI9BRwj4bo0kwZDn8jyedxhSRdU9CFlMs19CvbVnnLWeRGHScrTxpduVJZygbJcrRp6AWQqkeY0DzI4bd7uXgTIHXN6R403ALckZgqOWcUSEWj6THI9NFAIPP1LEnctaK0uxbzjpS1ize16r388StXBGq1we7Qa8j6xqJsN5GmnIN4HQ4W4PZIjGRHUZC8Q4ytXYE\r\nX-sxXe2ZUhl: Xbdhz13zW2HpxJ2AT4kRU1wDqBUkEQwvKtoebrfUGJ8bvjTMSxKihrDMk6BxAnY6kjFGDi5o8hcEag4tzJ1FhH9eI2UHDVbsDmUHTfAFbreJTHVlcIruAozmZKzi7XgTaOgzGhs75ytpE5dbRjCUt5P3kpExyNetXijJa3a2WMPiazmuQ98v6oAKLNHeGt1ePpm1rSHcBpCycOlb2kfdy8udyhMgpQCIz9Kwab44BAFYiPD8ulrTYGUGczGCccml7FtJk2NV7fRjtz6IZVtlWQZu3lBFGMaK72OIHtFv7qDKy5bZD9OSF6ERFeYDFok6x3YhShOxH1ruw0hRdM2u2gizX8Zuyr0puAM2JSEHDwMl0twtSzxHaxudDKUqB3UQqycaX0wCmJC0spZ81kaEpKMohlng6hajZyYSUecISZYnq7cYSDsTt2AKDGbj5GTiyymUr2AktpChMP2hXMFmBKG9GmmLyVyyzCMdJzIF01rBrPMvMV4SZNecspVGkwoaeFPll7xfgwQgKMdAdanWTFkTkFcMaxTMmH0QdAXPK8D9DQwJU0l44wR15JsPmOhEQkHXbuH9Wie2QbvvyLXOneai2RjHt7wlE1NlTrIgRF8kB9dFQm4oWeTEUqK7DW8l6dpo8Rzo7qedheulYQjnd8BXIAXlvaZZGY3PlpRQwruF2TvWtLLhH3awHv\r\nX-gkSXVCIKFmmkB17kFFmjYxPUyJ3: xYeCTDNLNkRaGviVUq65RlZ0V3kEviLihuTwLhZhftGZYtmzQXaDau6dCF5HPOj0n2Hzm5zd3xLDN63Y784E1zW5dmLOSZsDlHdOLJLQ87n7BS1cAVYJISLc1zR3PDqYVc6VO\r\nX-BMLZnLatiBQBQhhsmoIN: TygXEfWAlfPTPz5MtK0pQGVeDQABygr7SS5WPPcHbY56YMNSOOUH3sr1bsP9XLNdfuSEcBxxX5QpawCvRUmAGsWPKiom2Vi1gqsjp5nb7wK\r\nX-RDleXdm7e: Cd8Hz0JXAwRozVeaPwRKRDnJdDHQiE9akGgR321l3bzO7WfI4dcfi6RcvQI73sHMgUrLdoAUtcNlv9nyEuM53lwEpkQSle1ujwAx5JyhwxMG8zkjmkeyTmsjOdz84RDdbDh1z2bk4VnqKdxd96YyQAki7NB7CCT06MenVNxazMxABkKqgc6CcBNTvRkH1GJPSd18qSCdRj4T\r\nX-XMjt4CUDRsmqKlqovbEzW: jeHYYvPKTNn4lnSH8Ygsn0ov0kqQ0aoQugeUXPsT33ibtiRXbNwXeF5nhxic0BEVI8yh2jwjZFBjHBBHZkNsybgrTitkQwq5rDITuA0UgirFVYC99HsLzc2fBQySOVvvFhqCbo3TPHsdjhwxQ4Y6Fz69qTRtgWhmJFM9q3Q7RE8ZOt91RdGcKFkkU3yyW1Kr7e7Ozw494BoHFP3p0gXOidzZ1EA7aUF6YRE4gxRIJkfeJswjgO9Xg4crhyusIl4CRPDVwydl4WSH3xa4EtZa8zvTOS5gbkmUsDSNzxfhSMvbniHetQBYQtblyYwMEwzuoOxKbOmNEWPdOqZLfbWurU39CZ94Af4uGSWu7ZNMlTf3c74Too5Zvdc0qKURAnmiBwWt6xWncBVCgyGmj1kXz6SmZuPxbVBJzRLA3D592kUTvFU9EpQQ5FgWDIcpKmcfsLibxHnm36FJYMoh7OtPEW0CHtIFnPPpZWZZTdJL9janSIBjyxu3KKYfrbNO3FXqnxlmL14rYRVeSZdlxoxqfnL41OgB51Bk6ZMIyMYTDKH0cOIujjRX911MtH6vuneTqtyBrSO7Zl44IyiaLsLokxMRfKwKLdiKMxnwKC5vLuz0p6bDQANmEDTRQHYLW8bCIIZm0hYVEfzLlHW8q7f2JzzSXTZ5FZtvYz7sa4\r\nX-r5geOHg9B2v8t2raPEKVnqreWA: 6Mbr29vWf0iiqE6kTsRwvGGwJcN4JVCJu4kc0AK8NrClHXeRDviQzSy9qScj1axnquFcrTKKJbjLgmfzWb5Vh9spzrjp6X9o0X6Ipt8vPkBelqATGdDfdQDa9GplLR39rDUb3cOOQj1mrbmXU7XigBWV5EtonYWR0aIFhW6SKdLeH6eqVHZs22TZt5qD0UxT5lh8sZH8lU6iQtonhhBJXEYGhy8Y90735Kdv4cYDSVGUV3baZAuD1lH4QLLsC2FR69OFORpuseiDAdsssz9ARdbiyzk7Ve4lRmPBPpWtRs1WNyvCLJyo2zvEKxG2sIIIslSCFd5lkqdbR6LxIYDwL5yP5D2k8nVd1D4L3PtaPhL3Fe6E7glr98td6bnbdILhOmLK2ZgyoGeW7LjUEEx0d9bvToaaJyfeRH4zjJcvw3H1D7HIlFh3cumxI6BCQ9CLfKUkO40HdFOyuPzgX5bGJ4BLX8Go8kMjF6MSABUNawrVONoDpRFabrtpNtw46RWfZcNHaRErve9c5I6bGH134a7LldxUd3493cX5JAmTHymD8el4pF7Qa9fGZLRffUan1yKmE7nPNjm7LnLw2k\r\nX-Lzi6QcJlIRwscZe7l77e576: MBbKD9Qb8GAHZD740ksVx2IvmqhkEbNNpIGeMiDoQFo3d1WlX76kr7iGGYMRfwlAKxsEf8KdhpwNTpMszrQ4ylOkyEyvAxlLsFouQQKFXvDmwSeQfqvVh3KsfTCTfyTnn9hs0s2e6nMQQGEtU6eM71haSG4CauZNb5ltVr4F5xZM0Gv9JKIaQfelmw8GwG3BvB9VuAWkaUUnixu9ebkJI0UXwn7rqN4v5JbaliGptlG6VDLqLdOTarQj0RQK58JjZazPbEmVnx1XsmrrWcu\r\nX-GNNRo9eESwCbIrPz: veNcuOyuthE0K0SkI36JuNMdOoNJu8MldtLspxY7IP2gsQyzsyxLPZVWRc6bsIbcnrnje0p2J20rRyQAaH2S6L56MNIoSRqsiLXGOu2yrBOlG5vsJDJ707ieBmOQeyNWujXldtqaSWGKrBJawPRTTBbzkjJpN1GYK5rlFo0POVAjhOGY2DElofbypDipNxRqotKmqDb8PyikqnysU0ZLsRFT\r\nX-EfdqybgrpSdN: sJ2IZhRxvQxHeQW7lJuMY91W4OthEF9MpMAFWphxzBKG6QHbmrUpSzqGmixKnoobe7ki7Zb46fwrDAl3nMULM4ybv5VsMvRnfvd3BlAXNIU1SQNIGbljoaeM5tQ6XyqI32Q19SKPm9YkvADaUvvhYSoJIHcvpTWD3O3CXrYUj6ugiqclkS3qjnjBdUljuibx7OqebzEEGppDnskbNsAKdOAAg0LdFF5eSqQ3RLJJaMAnc2NX65wbrZUvMYFiM7rP7VkxsMwiFU8fiXTVv6GEJYvgKabQiW9ccxOlZFCjLzNj4feFdb51B9oacnnhpvtg5E2ALzjEaPxcqQ0G4fC8RyBghmEeE7PV5zmKQCu9uugnX9BkZIvbAjav0qWfBdDDi0kquUpFYT2lDTXweeZHqMEwbMvK8r1uKzrGHAzigXAHeSgCmMA8IDNaDmGGU6CVv06uSQ5rhqFdPZt1Yk85A9NMGxxDgzxjNLREXvKm01mwkdZjHAAIDGl8HzNS4RDIvr9DsL1xyKrPbmjS91jVc7hZKB6VZK4pNzCSUHo4VluTa3GAI8V7vlDuopc53knBz9tF6bfoJ14HjvFpc26VLDSjupRvb2vJTHHlrsuuihK3FcugTnefvvBgox3t3u2AlVWbFtjtj8oDcb7JrDrLzWqqEd8sCeFvMRP4pYVoD8uwfGzhvLnID3r2np2ZtGHodFmDHyrXYydzR4rhwOqqQv1Bq1Az4PQIpU92rZA7xnCGDeNU0LLFwQNIbGs2qEopP8AnlGzd6vZMA0yxc6HBswyHoao9wuWOfV0HkQGqUmEQiv47vOvnPYOK2EUpo0L81dD0sa8bC8C9Xtc51Sv7BEkRYZrMiV4yJkrpGRf6yvsGyQecLgmZmdCTMSApWRqEESFOKydTiDIaSEHqdjPutD6DGClY37jDHbyCwHKt7w5F0oW0rBGcFoKHdkSv87Cpdgx80ZkTg1ba44ctXSFBViBdtiOqeJ2bHMdkmcxVXlUNtoyp2BI\r\nContent-Length: 0\r\nTestMe: bob\r\n\r\n"
		assert_equal(expected, h.to_s, 'junk headers')
		h.headers.cmd_string = "HTTP/1.0 OK\r\n"
		h.headers.fold = 1
		expected = "HTTP/1.0 OK\r\nX-nsJxRxZX5o5zKaNf8VhtBgr3Gieuamk:\r\n\twM0v0nww3ZA8mepvkmcqXPmmWwHlyCNUudg03Tss4WWsl8i92mVcwi9B2tuR0irNRfVitBFvymfcm6ywElHD2VV5aCcvglhj6gnRJjsWFWJ2B9rFqEH2Tyzm13NLXm21Lo1fD39CHCZuFQyIR4ycO4GN4cDs7mvEALmGzU4GQAD7Fv9n7QZ5ebLoAhZ0Owi0oyyr3mTqimVUajbDZ8HEE1JEhxKX5wgNVcXwF9CAJHdVQOTlaMPTSqCQ4LjJ5JeWqUpTEuPhAvPNJxqKxninwssqBIALaerqTVvB68ScL7x0nJYEa0r2VOdBOAPhg9zlFe2pvy6J1HeVepIBtVI5tx0AbywZdHafO5TIndXNoBZYepQ8LnHmVYlr7kgJxoQj3Dnl6Do6jBDLDu7MgnyA22vXH7BiN4eVRXjhGYi3o5mJYdFwwZEumA7OJkvycPCkHRfrpPc202q4fW5yX8EARGELgQC6Knm28n93AJLs0RkpvFpwmkE7xLndrtLqgBsviqqsKq8ounPtaposwQrcAs9CW8YsTeNHTj11dUIKpiu9L9I13V0EvH44VWGTrGg7lWpV0LrDgdVRFvbBhorn5rzleS2P8ztodE4w4qUQ1VCUt4YrUtPhYYob9DTMysKJc1ufXNFtoHpuQynjqc\r\nX-RlBRei0DhrZBi4xnoSp2VvcBpm:\r\n\tPcZ7y1WbNhO1IEu2VtcWOAyl2yJh0oozHady5RKrhBm9TdGFEC3ooQHoYX06WpG4OznYfUSjgUYgbs6kSWifyS8OHLK56mpWAiRq0GDo7bMnVZAri9BwrlurZXqzE0HdBXXYZFWxQfwAyDhfG0AIYGLE1lH3ZzqFlE8q5MQ5FNLWqnAYwb3eYcYe50ug9ujWvIDk0O8k7R7TYYjyBMUHWs4PghNBDn4kmb6itmvZQwyJZAP1Qq9kHXxomtlxlEiW86xe7hbHNZlfk6xv1nISUZndCoyRonhDa1vYxez5BqSHrF6olTiVkYeBAYtv4EAk8y3UEF9OWPTM9ng5eUU6FKYLV8GB0NPvrVDdJ2Y3k8634xUl19uToDlDUmehZps3WlC5buzl64c8j\r\nX-hZ2KnIRZHzdnpUhx48KM:\r\n\tCgY1FTARXuU6kkMskPl2Yt0U68HuXUFHkvJFZhUAhTJCQX96yZ6qQRo8R69xlpmMGvYhOFJlmLZQT96Xy5wJqppna32qLHbg9eWdgCWvovY2zOCDhqkAYym3M9PaX4dQSth2D6mH5UwYC8KziYAGNmZbvFt9pXz2YNVNC4pB6t0A58OkHwJsxEQQ5QDo2Cg5GVcWb5xEEfCZeLKCLMUJ6jzGfbKwIZlPaFSAkglSNTCv5opAmAJxDFR8StLA1mspRsSGP28nAlkHtLEGm8oGQiQg4ckgxwIVyYQVKgI7lGaqb6tZUUNiEwOYBnrNkhMQ5Fh7fIh2AgfCqbQXCHltUAHZYBjeiciVXRFDZV7G9TWXVMW8KOs5pFn1zK9aaTu0QBTOJs8jjIa4zotN9Zs0OwN6Gr8ImzOucdfeIrC4P44cilqmlYFO4iLQfyM67A9i5A45QEkDFe7yqUwtPlp1cb377t39hLbiYNHYBjSuo3BqbPPpNG6gc40GOfGh66uazg87ufHxnBFlbmtXMJddNXYJEl4LW8Yloo01iuh6NhHMJudM\r\nX-w2ji68BRrw3J359QDpWvUYh76UVk:\r\n\tMaC66WuT5SifDAbwuW0D8gLwYcoJCO70KEJtar9Ilois2mbw66x1Tjk8KxSEYPxeNzQ3otL9iRGYddCL6uoRnJraU5EqC0nT0HfgE0bYq3Is1ambirMvIo4tgAvRMQ14LPczAuck8SRZoZEKhWhuSjwUF6jvNoneLI5aofaylT38fGzlLPs1EjyRsZ26MAgGjpoT7jdqXZU7sImWny1PELaLaMcAF5mNW77Y9aFSsucDXJzFahBgU59vbqMftb6DzUKzJFN8oR6tZDA2O0OXGPF2AnH9Rg6dfPLrfSrmWH0jTFxArBy186O05SpGkrxgLX7YyI1TCycm4urh0NthKzX9NzueArHDuAfIDLXUBGu8Eqj8vWemL0i3DxqAGhdVO0WbDxenuXYrNggy2xZJlsRXj75jiUFUGIA9sZmHJ6GdFkdnTvWDH4dUISWWVun4i8iQNc47Nh6aN59K6XVbt38VfmSb9aXHNUejKjFlWhSAfsetCVSQjMI8a8jJfsxrvAt82Ucmkehjp2auSYYOcypTCqx6dBV2R3ZO5WPySL2YFrG9p8rvMMtlSJI1oIAgM0U571yPX2sRXJtigpG3bjTmBhlhhDWl6yhDNiPrhepcJLZw85J8gVkLj45sCgck4Kjd9rpXldh9jqQUhDftkIYZZlKgDVoNgqFVoNbiA35snwvz7Rg4gLqGShz0FR2KMpRfDoiqeGAEEsAzjWendWXxa24LCVMQCbM155pjA9NlS\r\nX-KTsbJwm6:\r\n\tvmxmFWMC7AxYqdcgEIStcHIQWqPUwVXhCwaLYPvZFW2zidMs68UuhLueu4LGfipVKbRm5GL9wdNuT5H5QGoPCKpqodKKfR7jkk9RxVbZv2Ih6vJLwvcQwCIh7wOoBufWtAMo4Acf8c845Tzgqr3EyRdmaZSzUv5pHicgxmMYuuHJ8nthej8inCd4nWj1AaE1rvJGdFB8WadFQasaOYITd37LuVC95a1wrE5WSmBE9nTbHw1diY5MFsNwmPAxzEtWe9g3ftkD8jTiRsD8IBPpI40WKsMDWMZ1aopA37m0bokVVGMHD4Kb5xxYxuJsskIJjBmUtZsZFAn6GGnyRLRle5yxJMRkgD52M1vl0Hu9FRSSRhKxJaEoZylHhR8vnwRmIm6X3ilbECtxZGKTtPU1P2jvHo8kxcsuJkXjcSOnUkIwnN3roV7v9ggeJb9c4rXc4CUWgH4VUTZvlYT3qNsbWbD5hdVCmYRNJpZlOdvH6bcWEDYna6J7p03HULGctCn56bfjMAXF3AjKdRwoS70v9KTlN5DkDjH2KUcIIRR8Ffd7Q50WjyjQ1bgvCLSYYAt8IXB7dvmmsyyRT9ZF7uVihmybplx8ETzhVEzZ9zH4kzf99vC5ZM0959Fje00JxzR4dL9ir46rh6cWZbRhh0ZU7HAMxHsXmC7JeyaMSnxd6um3GC8xN4zQfIpnfZSTcB5azeV0Lji92A5Yugo6Edz240S0lnCzhZbtWqxG1dgnXlKJBADZ9oMDibxBImhrfdw88tNOcQjYtGS4h\r\nX-IOSp7nYMJwhxhyYPunG9RIvBHUoI0A3pC:\r\n\tW8KeIV35tDFbaMAD9rgoUOYDgJGD6cDPg\r\nX-sc1yFBRvIJ0:\r\n\twpYEHFnUDBJaBowmuVMGgqUMWUthgJ7kDpIczNXHzMCktNXn752JnPLJBaLfw6LB5IZ4ehsXUxIAiemUlW9qwWpUrHB4teMF4VFQrXolvwnomr6wAJ8P0s1EcxjUGpfZQEuNhRvBZvWqWRDTud2EUtesPh8ETl0ARRxnoSFiD6A3jZUdBOsmEGRd94BQCOqxYF5VIIhFg1ArzGOlcQ1d0Sd46lDqKpnggcOfi9ljDNSR9iiTyELVDxiTaIpOjMRqXRgxLoCwWEpqP78RnNfj8xD6tZzcSsfXuKNNNTBDMIzK9G0f3rfVNHtcSd9ayPuBtzZS1nwtWbLsmxAJWF9XGWXB33afT9ZoHL753R2oALkjN8ImKZpJ2UE7nQSuOXu0j7weDKgVp6uhShzM0CZqezcpRO78NhW09YeKDfxgNxnAuYUrpabXaJhapvfofIxkReB6d1QUI3kd7rsPNZlQyLuChcapBaITb5jWZYsUk1YeM03q4cyEBFsV6xYI4s6w6egVD51URRLS5j6VtrizhJbXpz7kwhLtIrudhvOeufXrVCakuJB4DRBweihvwK5GFqGpmF8e7IR3WDPmu0eGdWKcHbwTCzHMzTzeebPvX6eTINmmCqzEmF71uyhYscV9sOy0EpRPZkMm7deiTqTfpkpLHFNiuggcMdzKq3Jzx7TWXe80Nyf68QSBPgOJGzvDG2PdVzK6NbaapE7dwc98Pu5bogtxOEZgMsp7q0N0y4yxFXl0ec2VTY5vXtKegVo2eGZF3fvubZhbQQPei7FIQmzncFATX8e0umoiRPKSobz8qmOvR83psDw1ZYsfX9PV8dWYDJmAPspOFR6pDwTSrxxBHIf8OOUSvjsonfBa5Ympf4Lw7jLxvxxyvytdky5Kqa8L5pH90gbH3U\r\nContent-Length:\r\n\t0\r\nTestMe:\r\n\tbob\r\n\r\n"
		assert_equal(expected, h.to_s, 'junk headers')
	end

	def test_pipeline
		req_normalized = 
			"GET / HTTP/1.0\r\n" +
			"Foo: Bar\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"Super body"

		req = req_normalized + req_normalized
	   
		req_base = req.dup
		req_fold = req.gsub(/:/,  ':' + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t") + "\r\n" + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t"))
		req_nocr = req.gsub(/\r\n/, "\n")
		req_junk = req + "junk"

		{ 'base' => req_base, 'fold' => req_fold, 'no cr' => req_nocr, 'extra junk' => req_junk }.each_pair { |name, test| 
			h = Klass.new
			h.auto_cl = false
			assert_equal(Klass::ParseCode::Completed, h.parse(test), "parse #{name}")
			assert_equal(req_normalized, h.to_s, "to string #{name}")
			assert_equal(true, h.completed?, "completed parsing #{name}")
			assert_equal('Bar', h.headers['Foo'], "first header #{name}")
			assert_equal('10', h.headers['Content-Length'], "second header #{name}")
			assert_equal("Super body", h.body, "body #{name}")
		}
	end


	def test_chunked
		req_start = 
			"GET / HTTP/1.0\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Foo: Bar\r\n" +
			"\r\n"

		req_normalized = req_start + "Super body"

		req = req_start + "1\r\nS\r\n1\r\nu\r\n1\r\np\r\n1\r\ne\r\n1\r\nr\r\n1\r\n \r\n1\r\nb\r\n1\r\no\r\n1\r\nd\r\n1\r\ny\r\n0\r\n\r\n"
		
		req_base = req.dup
		req_fold = req.gsub(/:/,  ':' + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t") + "\r\n" + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t"))
		req_nocr = req.gsub(/\r\n/, "\n")
		req_junk = req + "junk"

		{ 'base' => req_base, 'fold' => req_fold, 'no cr' => req_nocr, 'extra junk' => req_junk }.each_pair { |name, test| 
			h = Klass.new
			h.auto_cl = false
			assert_equal(Klass::ParseCode::Completed, h.parse(test), "parse #{name}")
			assert_equal(req_normalized, h.to_s, "to string #{name}")
			assert_equal(true, h.completed?, "completed parsing #{name}")
			assert_equal('Bar', h.headers['Foo'], "first header #{name}")
			assert_equal('chunked', h.headers['Transfer-Encoding'], "second header #{name}")
			assert_equal("Super body", h.body, "body #{name}")
		}
	end

	def test_content_length
		req = 
			"GET / HTTP/1.0\r\n" +
			"Foo: Bar\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"Super body"
		
		req_base = req.dup
		req_fold = req.gsub(/:/,  ':' + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t") + "\r\n" + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t"))
		req_nocr = req.gsub(/\r\n/, "\n")
		req_junk = req + "junk"

		{ 'base' => req_base, 'fold' => req_fold, 'no cr' => req_nocr, 'extra junk' => req_junk }.each_pair { |name, test| 
			h = Klass.new
			h.auto_cl = false
			assert_equal(Klass::ParseCode::Completed, h.parse(test), "parse #{name}")
			assert_equal(req, h.to_s, "to string #{name}")
			assert_equal(true, h.completed?, "completed parsing #{name}")
			assert_equal('Bar', h.headers['Foo'], "first header #{name}")
			assert_equal('10', h.headers['Content-Length'], "second header #{name}")
			assert_equal("Super body", h.body, "body #{name}")
		}
	end
		
	def test_parse_connection_close
		req = 
			"GET / HTTP/1.0\r\n" +
			"Foo: Bar\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Super body"
		
		req_base = req.dup
		req_fold = req.gsub(/:/,  ':' + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t") + "\r\n" + Rex::Text.rand_base(rand(10) + 1,'',"\s","\t"))
		req_nocr = req.gsub(/\r\n/, "\n")

		{ 'base' => req_base, 'fold' => req_fold, 'no cr' => req_nocr }.each_pair { |name, test| 
			h = Klass.new
			h.auto_cl = false
			assert_equal(Klass::ParseCode::Completed, h.parse(test), "parse #{name}")
			assert_equal(req, h.to_s, "to string #{name}")
			assert_equal(true, h.completed?, "completed parsing #{name}")
			assert_equal('Bar', h.headers['Foo'], "first header #{name}")
			assert_equal('close', h.headers['Connection'], "second header #{name}")
			assert_equal("Super body", h.body, "body #{name}")
		}
	end

	def test_to_s
		h = Klass.new

		h.headers['Foo']     = 'Fishing'
		h.headers['Chicken'] = 47

		assert_equal(
			"Foo: Fishing\r\n" +
			"Content-Length: 0\r\n" +
			"Chicken: 47\r\n\r\n", h.to_s)
	end

	def test_from_s
		h = Klass.new

		h.from_s(
			"HTTP/1.0 200 OK\r\n" +
			"Lucifer: Beast\r\n" +
			"HoHo: Satan\r\n" +
			"Eat: Babies\r\n" +
			"\r\n")

		assert_equal('Babies', h['Eat'])
		h['Eat'] = "fish"
		assert_equal('fish', h['Eat'])
	end

	# XXX
    def test_no_headers
        h = Klass.new
        h.from_s("GET / HTTP/1.0\r\n\r\n")
        assert_equal("GET / HTTP/1.0\r\n", h.headers.cmd_string, 'cmd string')
    end

end