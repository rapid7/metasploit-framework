FactoryBot.define do
  factory :mdm_module_detail, :class => Mdm::Module::Detail do
    transient do
      root {
        MetasploitDataModels.root
      }
      modules_pathname { root.join('modules') }
    end

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

    stance {
      if supports_stance?
        generate :mdm_module_detail_stance
      else
        nil
      end
    }

    file {
      type_directory = Mdm::Module::Detail::DIRECTORY_BY_TYPE[mtype]

      modules_pathname.join(
          type_directory,
          "#{refname}.rb"
      ).to_path
    }
  end

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

  sequence :mdm_module_detail_privileged, Mdm::Module::Detail::PRIVILEGES.cycle

  sequence :mdm_module_detail_mtime do |n|
    Time.now.utc - n.seconds
  end

  ordered_types = Mdm::Module::Detail::DIRECTORY_BY_TYPE.keys.sort
  sequence :mdm_module_detail_mtype, ordered_types.cycle

  sequence :mdm_module_detail_name do |n|
    "Module Name #{n}"
  end

  ordered_ranks = Mdm::Module::Detail::RANK_BY_NAME.values.sort
  sequence :mdm_module_detail_rank, ordered_ranks.cycle

  sequence :mdm_module_detail_refname do |n|
    "module/ref/name#{n}"
  end

  sequence :mdm_module_detail_stance, Mdm::Module::Detail::STANCES.cycle
end
