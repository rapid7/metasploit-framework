desc 'Show some stats about the code'
task :stats do
  line_count = proc do |path|
    Dir[path].collect { |f| File.open(f).readlines.reject { |l| l =~ /(^\s*(\#|\/\*))|^\s*$/ }.size }.inject(0){ |sum,n| sum += n }
  end
  comment_count = proc do |path|
    Dir[path].collect { |f| File.open(f).readlines.select { |l| l =~ /^\s*\#/ }.size }.inject(0) { |sum,n| sum += n }
  end
  lib     = line_count['lib/**/*.rb']
  comment = comment_count['lib/**/*.rb']
  ext     = line_count['ext/**/*.{c,h}'] 
  spec    = line_count['spec/**/*.rb']
  
  comment_ratio = '%1.2f' % (comment.to_f / lib.to_f)
  spec_ratio = '%1.2f' % (spec.to_f / lib.to_f)
  
  puts '/======================\\'
  puts '| Part            LOC  |'
  puts '|======================|'
  puts "| lib             #{lib.to_s.ljust(5)}|"
  puts "| lib comments    #{comment.to_s.ljust(5)}|"
  puts "| ext             #{ext.to_s.ljust(5)}|"
  puts "| spec            #{spec.to_s.ljust(5)}|"
  puts '| ratios:              |'
  puts "|   lib/comment   #{comment_ratio.to_s.ljust(5)}|"
  puts "|   lib/spec      #{spec_ratio.to_s.ljust(5)}|"
  puts '\======================/'
end
