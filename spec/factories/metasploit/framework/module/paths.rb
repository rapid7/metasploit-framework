FactoryGirl.define do
	factory :metasploit_framework_module_path,
					:aliases => [:unnamed_metasploit_framework_module_path],
					:class => Metasploit::Framework::Module::Path do
		real_path { generate :metasploit_framework_module_path_real_path }

		factory :named_metasploit_framework_module_path do
			gem { generate :metasploit_framework_module_path_gem }
			name { generate :metasploit_framework_module_path_name }
		end
	end

	sequence :metasploit_framework_module_path_gem do |n|
		"metasploit-framework-module-path-gem#{n}"
	end

	sequence :metasploit_framework_module_path_name do |n|
		"metasploit_framework_module_path_name#{n}"
	end

	sequence :metasploit_framework_module_path_real_path do |n|
		pathname = Metasploit::Model::Spec.temporary_pathname.join(
				'metasploit',
				'framework',
				'module',
				'path',
				'real',
				'path',
				n.to_s
		)
		Metasploit::Model::Spec::PathnameCollision.check!(pathname)
		pathname.mkpath

		pathname.to_path
	end
end