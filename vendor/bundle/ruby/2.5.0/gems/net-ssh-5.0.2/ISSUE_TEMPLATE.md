### Expected behavior

Tell us what should happen

### Actual behavior

Tell us what happens instead.

### System configuration

- net-ssh version
- Ruby version

### Example App

Please provide an example script that reproduces the problem. This will save maintainers time so they can spend it fixing your issues instead of trying to build a reproduction case from sparse instructions.

You can use this as stating point:

```ruby
gem 'net-ssh', '= 4.0.0.beta3'
require 'net/ssh'
puts Net::SSH::Version::CURRENT

@host = 'localhost'
@user = ENV['USER']
Net::SSH.start(@host, @user) do |ssh|
  puts ssh.exec!('echo "hello"')
end
```
