#!/usr/bin/env ruby
require 'fileutils'

def prompt(*args)
    print(*args)
    gets
end

#
# Functions we can't live without
#

def print_status(msg='')
  puts "[*] #{msg}"
end

def print_error(msg='')
  puts "[-] #{msg}"
end

# The path for all module docs
DOCS_PATH = File.join('..', '..', 'documentation', 'modules')

puts 'This tool generates documentation for your local module.'
puts 'This tool does not cover everything in the doc! Feel free to go in and add more stuff.'
puts


module_path = prompt('Full module path (e.g. exploit/windows/smb/ms08_067_netapi): '.gsub('.rb', '')).strip
intro       = prompt('Write a quick introduction for your module: ').strip
vuln_apps   = prompt('Vulnerable applications (Windows XP SP1, Windows 7): ').strip
vuln_apps = vuln_apps.split(', ')
options     = prompt 'Options and their descriptions (RHOST:The remote host, RPORT:The remote port): '
options = options.split(', ')

md = ''
md << "## Introduction\n"
md << intro
md << "\n\n"
md << "## Vulnerable application\n" if vuln_apps.length == 1
md << "## Vulnerable applications\n" if vuln_apps.length > 1
vuln_apps.each { |v| md << "- #{v}\n" }
md << "\n\n"
md << "## Options\n"
# Go through each option and put each option (opt[0]) and description (opt[1])
options.each do |f| # f is in the format "OPTION:description"
  opt = f.split(':')
  md << "  **#{opt[0]}**\n\n"
  md << "  #{opt[1]}\n\n"
end

md << "## Scenarios\n\n"
md << "Specific demo of using the module that might be useful in a real world scenario.\n\n"

md << %Q|For example:

To do this specific thing, here's how you do it:

```
msf > use module_name
msf auxiliary(module_name) > set RPORT 8080
msf auxiliary(module_name) > exploit
```|

begin
  full_mod_path = File.join(DOCS_PATH, "#{module_path}.md")
  dirname = File.dirname(full_mod_path)
  unless File.directory?(dirname)
    FileUtils.mkdir_p(dirname)
  end

  f = File.new(full_mod_path, 'w')
  f.write(md)
rescue StandardError => e
  print_error "Unable to write documentation: #{e.class} - #{e.message}"
end
