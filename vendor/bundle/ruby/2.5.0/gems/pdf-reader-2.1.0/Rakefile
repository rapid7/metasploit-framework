require "bundler/gem_tasks"
require "digest/md5"
require "rdoc/task"
require "rspec/core/rake_task"
require "yaml"

desc "Default Task"
task :default => [ :quality, :spec ]

require 'cane/rake_task'
require 'morecane'

desc "Run cane to check quality metrics"
Cane::RakeTask.new(:quality) do |cane|
  cane.abc_max = 20
  cane.style_measure = 100
  cane.max_violations = 31

  cane.use Morecane::EncodingCheck, :encoding_glob => "{app,lib,spec}/**/*.rb"
end

desc "Run all rspec files"
RSpec::Core::RakeTask.new(:spec) do |t|
  t.rspec_opts  = ["--color", "--format progress"]
  t.ruby_opts = "-w"
end

# Generate the RDoc documentation
desc "Create documentation"
Rake::RDocTask.new("doc") do |rdoc|
  rdoc.title = "pdf-reader"
  rdoc.rdoc_dir = (ENV['CC_BUILD_ARTIFACTS'] || 'doc') + '/rdoc'
  rdoc.rdoc_files.include('README.rdoc')
  rdoc.rdoc_files.include('TODO')
  rdoc.rdoc_files.include('CHANGELOG')
  rdoc.rdoc_files.include('MIT-LICENSE')
  rdoc.rdoc_files.include('lib/**/*.rb')
  rdoc.options << "--inline-source"
end

desc "Create a YAML file of integrity info for PDFs in the spec suite"
task :integrity_yaml do
  data = {}
  Dir.glob("spec/data/**/*.*").sort.each do |path|
    path_without_spec = path.gsub("spec/","")
    data[path_without_spec] = {
      :bytes => File.size(path),
      :md5 => Digest::MD5.hexdigest(File.read(path))
    } if File.file?(path)
  end
  File.open("spec/integrity.yml","wb") { |f| f.write YAML.dump(data)}
end

desc "Remove any CRLF characters added by Git"
task :fix_integrity do
  yaml_path = File.expand_path("spec/integrity.yml",File.dirname(__FILE__))
  integrity = YAML.load_file(yaml_path)

  Dir.glob("spec/data/**/*.pdf").each do |path|
    path_relative_to_spec_folder = path[/.+(data\/.+)/,1]
    item = integrity[path_relative_to_spec_folder]

    if File.file?(path)
      file_contents = File.open(path, "rb") { |f| f.read }
      md5 = Digest::MD5.hexdigest(file_contents)

      unless md5 == item[:md5]
        #file md5 does not match what was checked into Git

        if Digest::MD5.hexdigest(file_contents.gsub(/\r\n/, "\n")) == item[:md5]
          #pdf file is fixable by swapping CRLF characters

          File.open(path, "wb") do |f|
            f.write(file_contents.gsub(/\r\n/, "\n"))
          end
          puts "Replaced CRLF characters in: #{path}"
        else
          puts "Failed to fix: #{path}"
        end
      end
    end
  end
end
