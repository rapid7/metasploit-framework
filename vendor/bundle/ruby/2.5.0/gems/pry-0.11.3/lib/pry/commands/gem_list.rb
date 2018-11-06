class Pry
  class Command::GemList < Pry::ClassCommand
    match 'gem-list'
    group 'Gems'
    description 'List and search installed gems.'

    banner <<-'BANNER'
      Usage: gem-list [REGEX]

      List all installed gems, when a regex is provided, limit the output to those
      that match the regex.
    BANNER

    def process(pattern = nil)
      pattern = Regexp.compile(pattern || '')
      gems    = Rubygem.list(pattern).group_by(&:name)

      gems.each do |gem, specs|
        specs.sort! do |a,b|
          Gem::Version.new(b.version) <=> Gem::Version.new(a.version)
        end

        versions = specs.each_with_index.map do |spec, index|
          index == 0 ? text.bright_green(spec.version.to_s) : text.green(spec.version.to_s)
        end

        output.puts "#{text.default gem} (#{versions.join ', '})"
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::GemList)
end
