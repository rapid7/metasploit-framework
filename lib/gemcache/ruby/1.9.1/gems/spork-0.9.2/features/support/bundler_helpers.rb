require 'bundler'
module BundlerHelpers
  extend self
  def install_bundle(dir)
    Dir.chdir(dir) do
      command = "env RUBYOPT= BUNDLE_GEMFILE=Gemfile bundle install"
      system(command)
      $?.exitstatus
    end
  end

  def ensure_installed(dir)
    gemfile_lock = dir + "/Gemfile.lock"
    gemfile = dir + "/Gemfile"
    bundle_environment = dir + "/.bundle/environment.rb"
    case
    when File.exist?(gemfile_lock) && File.mtime(gemfile) > File.mtime(gemfile_lock)
      puts "Gemfile #{gemfile} has changed since it was locked. Re-locking..."
      FileUtils.rm(gemfile_lock)
      FileUtils.rm_rf(dir + "/.bundle")
    when ! File.exist?(bundle_environment)
      puts "Bundle #{gemfile} not installed.  Installing..."
    when File.mtime(bundle_environment) < File.mtime(gemfile_lock)
      puts "#{gemfile_lock} is newer than #{bundle_environment}.  Reinstalling"
    else
      return false
    end
    install_bundle(dir)
  end

  def expand_gemfile(gemfile)
    possibilities = [File.expand_path(gemfile, Dir.pwd), SporkWorld::GEMFILES_ROOT + gemfile + "Gemfile"]
    possibilities.detect {|f| File.exist?(f)} || raise(RuntimeError, %(Gemfile not found:\n #{possibilities * "\n"}))
  end

  def set_gemfile(gemfile)
    gemfile = expand_gemfile(gemfile || "rails3.0")
    ensure_installed(File.dirname(gemfile))
    ENV["BUNDLE_GEMFILE"] = gemfile.to_s
  end
end
