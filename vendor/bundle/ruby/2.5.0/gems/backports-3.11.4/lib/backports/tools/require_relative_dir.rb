module Backports
  def self.require_relative_dir
    dir = caller.first.split(/\.rb:\d/,2).first
    short_path = dir[/.*(backports\/.*)/, 1] << '/'
    Dir.entries(dir).
        map{|f| Regexp.last_match(1) if /^(.*)\.rb$/ =~ f}.
        compact.
        sort.
        each do |f|
          require short_path + f
        end
  end
end
