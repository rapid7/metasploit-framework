<%
rerun = File.file?('rerun.txt') ? IO.read('rerun.txt') : ""
rerun_opts = rerun.to_s.strip.empty? ? "--format #{ENV['CUCUMBER_FORMAT'] || 'progress'} features" : "--format #{ENV['CUCUMBER_FORMAT'] || 'pretty'} #{rerun}"
std_opts = "--format #{ENV['CUCUMBER_FORMAT'] || 'pretty'} --strict --tags ~@wip"
%>
default: <%= std_opts %> features
wip: --tags @wip:3 --wip features
rerun: <%= rerun_opts %> --format rerun --out rerun.txt --strict --tags ~@wip
