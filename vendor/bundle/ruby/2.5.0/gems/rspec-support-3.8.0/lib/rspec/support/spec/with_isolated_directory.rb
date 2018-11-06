require 'tmpdir'

RSpec.shared_context "isolated directory" do
  around do |ex|
    Dir.mktmpdir do |tmp_dir|
      Dir.chdir(tmp_dir, &ex)
    end
  end
end

RSpec.configure do |c|
  c.include_context "isolated directory", :isolated_directory => true
end
