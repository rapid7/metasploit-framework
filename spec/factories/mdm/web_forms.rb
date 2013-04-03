FactoryGirl.define do
	factory :mdm_web_form, :class => Mdm::WebForm do
		#
		# Associations
		#
		association :web_site, :factory => :mdm_web_site

		# attributes that would be in web_form element from Pro export
		trait :exported do
			method { generate :mdm_web_form_method }
			params { generate :mdm_web_form_params }
			path { generate :mdm_web_form_path }
		end
	end

	methods = ['GET', 'POST']

	sequence :mdm_web_form_method do |n|
		methods[n % methods.length]
	end

	sequence :mdm_web_form_params do |n|
		[
				[
						"name#{n}",
				    "value#{n}"
				]
		]
	end

	sequence :mdm_web_form_path do |n|
		"path/to/web/form/#{n}"
	end
end