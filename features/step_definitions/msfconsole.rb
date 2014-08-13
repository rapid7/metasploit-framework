When /^msfconsole is ready$/ do
    step 'I run `msfconsole` interactively'
    step 'I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"'
end
