Before('@msfconsole') do
  step 'I run `msfconsole` interactively'
  step 'I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"'
end

Before('@target') do
  step 'targets are loaded'
end
