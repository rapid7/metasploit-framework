FactoryGirl.define do
	factory :mdm_web_page, :class => Mdm::WebPage do
		auth { generate :mdm_web_page_auth }
		body { generate :mdm_web_page_body }
		code { generate :mdm_web_page_code }
		cookie { generate :mdm_web_page_cookie }
		ctype { generate :mdm_web_page_ctype }
		headers { generate :mdm_web_page_headers }
		location { generate :mdm_web_page_location }
		mtime { generate :mdm_web_page_mtime }
		query { generate :mdm_web_page_query }

		#
		# Associations
		#
		association :web_site, :factory => :mdm_web_site
	end

	sequence :mdm_web_page_auth do |n|
		"Authorization: #{n}"
	end

	sequence :mdm_web_page_body do |n|
		xml = Builder::XmlMarkup.new(:indent => 2)

		xml.html

		xml.target!.strip
	end

	sequence :mdm_web_page_code do |n|
		n
	end

	sequence :mdm_web_page_cookie do |n|
		"name#{n}=value#{n}"
	end

	sequence :mdm_web_page_ctype do |n|
    "application/x-#{n}"
	end

	sequence :mdm_web_page_headers do |n|
		[
				[
						"Header#{n}",
						"Value#{n}"
				]
		]
	end

	sequence :mdm_web_page_location do |n|
		"http://example.com/location/#{n}"
	end

	sequence :mdm_web_page_mtime do |n|
		past = Time.now - n
		past.utc.strftime('%a, %d %b %Y %H:%M:%S %Z')
	end

	sequence :mdm_web_page_query do |n|
		"param#{n}=value#{n}"
	end
end