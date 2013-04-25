FactoryGirl.define do
	type_directory_by_type = {
			'auxiliary' => 'auxiliary',
			'encoder' => 'encoders',
			'exploit' => 'exploits',
			'nop' => 'nops',
			'payload' => 'payloads',
			'post' => 'posts'
	}

	sequence :mdm_module_detail_disclosure_date do |n|
		# @todo https://www.pivotaltracker.com/story/show/48450593
		Date.today - n
	end

	sequence :mdm_module_detail_description do |n|
    "Module Description #{n}"
	end

	sequence :mdm_module_detail_license do |n|
		"Module License v#{n}"
	end

	privileges = [false, true]
	privilege_count = privileges.length

	sequence :mdm_module_detail_privileged do |n|
	  privileges[n % privilege_count]
	end

	sequence :mdm_module_detail_mtime do |n|
		Time.now.utc - n.seconds
	end

	types = type_directory_by_type.keys
	type_count = types.length

	sequence :mdm_module_detail_mtype do |n|
		types[n % type_count]
	end

	sequence :mdm_module_detail_name do |n|
		"Module Name #{n}"
	end

	sequence :mdm_module_detail_rank do |n|
		100 * (n % 7)
	end

	stances = ['active', 'passive']
	sequence :mdm_module_detail_stance, stances.cycle
end

modules_pathname = Metasploit::Framework.root.join('modules')
type_directory_by_type = {
		'auxiliary' => 'auxiliary',
    'encoder' => 'encoders',
    'exploit' => 'exploits',
    'nop' => 'nops',
    'payload' => 'payloads',
    'post' => 'posts'
}

FactoryGirl.modify do
  factory :mdm_module_detail do
	  description { generate :mdm_module_detail_description }
	  disclosure_date { generate :mdm_module_detail_disclosure_date }
	  license { generate :mdm_module_detail_license }
	  mtime { generate :mdm_module_detail_mtime }
	  mtype { generate :mdm_module_detail_mtype }
	  privileged { generate :mdm_module_detail_privileged }
	  name { generate :mdm_module_detail_name }
	  rank { generate :mdm_module_detail_rank }
	  refname { generate :mdm_module_detail_refname }
	  fullname { "#{mtype}/#{refname}" }
	  stance { generate :mdm_module_detail_stance }

	  file {
		  type_directory = type_directory_by_type[mtype]

		  modules_pathname.join(
				  type_directory,
				  "#{refname}.rb"
		  ).to_path
	  }
  end
end