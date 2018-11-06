class Pry::Command::GemSearch < Pry::ClassCommand
  match 'gem-search'
  description 'Search for a gem with the rubygems.org JSON API'
  group 'Gems'
  command_options argument_required: true
  banner <<-BANNER
    gem-search [options] gem
    Search for a gem with the rubygems.org HTTP API
  BANNER

  API_ENDPOINT = 'https://rubygems.org/api/v1/search.json'

  def setup
    require 'json' unless defined?(JSON)
    require 'net/http' unless defined?(Net::HTTP)
  end

  def options(opt)
    opt.on :l, :limit, 'Limit the number of results (max: 30)',
      default: 10,
      as: Integer,
      argument: true
  end

  def process(str)
    uri = URI.parse(API_ENDPOINT)
    uri.query = URI.encode_www_form(query: str)
    gems = JSON.load Net::HTTP.get(uri)
    _pry_.pager.page list_as_string(gems, opts[:limit])
  end

private
  def list_as_string(gems, limit = 10)
    gems[0..limit-1].map do |gem|
      name, version, info = gem.values_at 'name', 'version', 'info'
      "#{text.bold(name)} #{text.bold('v'+version)} \n#{info}\n\n"
    end.join
  end
  Pry::Commands.add_command(self)
end
