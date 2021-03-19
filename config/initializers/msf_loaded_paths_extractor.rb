require 'msf_autoload'

module MsfLoadedPathsExtractor

  def extract(loader)
    framework_managed = []
    config_paths.each do |entry|
      framework_managed << Pathname.new(entry[:path]).realpath.to_s
    end
    loader.ignore(ignore_list)
  end

end

MsfAutoload.send(:prepend, MsfLoadedPathsExtractor)

MsfAutoload.instance.extract(Rails.autoloaders.main)
