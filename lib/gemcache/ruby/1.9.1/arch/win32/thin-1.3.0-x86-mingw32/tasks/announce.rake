require 'erb'

MSG_TEMPLATE = File.dirname(__FILE__) + '/email.erb'
SEND_TO      = %w(thin-ruby@googlegroups.com ruby-talk@ruby-lang.org)

desc 'Generate a template for the new version annoucement'
task :ann do
  msg = ERB.new(File.read(MSG_TEMPLATE)).result(binding)
    
  body = <<END_OF_MESSAGE
To: #{SEND_TO.join(', ')}
Subject: [ANN] Thin #{Thin::VERSION::STRING} #{Thin::VERSION::CODENAME} release

#{msg}
END_OF_MESSAGE

  fork { `echo "#{body}" | mate` }
end

def changelog
  File.read('CHANGELOG').split("==")[1].split("\n")[1..-1].join("\n")
end