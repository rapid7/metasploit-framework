require 'anemone'

begin
  # make sure that the first option is a URL we can crawl
  root = URI(ARGV[0])
rescue
  puts <<-INFO
Usage:
  anemone pagedepth <url>

Synopsis:
  Crawls a site starting at the given URL and outputs a count of
  the number of pages at each depth of the crawl.
INFO
  exit(0)
end

Anemone.crawl(root) do |anemone|
  anemone.skip_links_like %r{^/c/$}, %r{^/stores/$}

  anemone.after_crawl do |pages|
    pages = pages.shortest_paths!(root).uniq!

    depths = pages.values.inject({}) do |depths, page|
      depths[page.depth] ||= 0
      depths[page.depth] += 1
      depths
    end

    depths.sort.each { |depth, count| puts "Depth: #{depth} Count: #{count}" }
  end
end
