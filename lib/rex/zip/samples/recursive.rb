# -*- coding: binary -*-

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
inc = File.dirname(msfbase) + '/../../..'
$:.unshift(inc)

require 'rex/zip'

out = "test.zip"
dir = "/var/www"


def add_file(zip, path)
  zip.add_file(path)
end


#
# If it's a directory, Walk the directory and add each item
#
def add_files(zip, path, recursive = nil)

  if (not add_file(zip, path))
    return nil
  end

  if (recursive and File.stat(path).directory?)
    begin
      dir = Dir.open(path)
    rescue
      # skip this file
      return nil
    end

    dir.each { |f|
      next if (f == '.')
      next if (f == '..')

      full_path = path + '/' + f
      st = File.stat(full_path)
      if (st.directory?)
        puts "adding dir  #{full_path}"
        add_files(zip, full_path, recursive)
      elsif (st.file?)
        puts "adding file #{full_path}"
        add_file(zip, full_path)
      end
    }
  end
end


zip = Rex::Zip::Archive.new
add_files(zip, dir, TRUE)
zip.save_to(out)
