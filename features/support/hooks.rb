Before('@msfconsole') do
  step 'I run `msfconsole` interactively'
  step 'I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"'
  # we should not see the following
  # -- --=[ 0 exploits - 0 auxiliary - 0 post               ]
  # -- --=[ 0 payloads - 0 encoders - 0 nops                ]
end

Before('@targets') do
  step 'targets are loaded'
end
