# Thin

A small and fast Ruby web server

## Installation

```
gem install thin
```

Or add `thin` to your `Gemfile`:

```ruby
gem 'thin'
```

## Usage

A +thin+ script offers an easy way to start your Rack application:

```
thin start
```

Browse the `example` directory for sample applications.

## Usage with Rails Action Cable

To use Thin with Action Cable, add the following to your `Gemfile`:

```ruby
gem 'faye-websocket'
gem 'thin' # If not already done
```

Create a `config/initializers/thin_action_cable.rb`:

```ruby
Rails.application.config.action_cable.use_faye = true
Faye::WebSocket.load_adapter 'thin'
```

### CLI

Use a rackup (config.ru) file and bind to localhost port 8080:

```
thin -R config.ru -a 127.0.0.1 -p 8080 start
```

Store the server process ID, log to a file and daemonize:

```
thin -p 9292 -P tmp/pids/thin.pid -l logs/thin.log -d start
```

Thin is quite flexible in that many options can be specified at the command line (see `thin -h` for more).

### Configuration files

You can create a configuration file using `thin config -C config/thin.yml`.

You can then use it with all commands, such as: `thin start -C config/thin.yml`.

Here is an example config file:

```yaml
--- 
user: www-data
group: www-data
pid: tmp/pids/thin.pid
timeout: 30
wait: 30
log: log/thin.log
max_conns: 1024
require: []
environment: production
max_persistent_conns: 512
servers: 1
threaded: true
no-epoll: true
daemonize: true
socket: tmp/sockets/thin.sock
chdir: /path/to/your/apps/root
tag: a-name-to-show-up-in-ps aux
```

## License

Ruby License, http://www.ruby-lang.org/en/LICENSE.txt.

## Credits

The parser was originally from Mongrel http://mongrel.rubyforge.org by Zed Shaw.
Mongrel is copyright 2007 Zed A. Shaw and contributors. It is licensed under
the Ruby license and the GPL2.

Thin is copyright Marc-Andre Cournoyer <macournoyer@gmail.com>

Get help at http://groups.google.com/group/thin-ruby/
Report bugs at https://github.com/macournoyer/thin/issues
and major security issues directly to me at macournoyer@gmail.com.
