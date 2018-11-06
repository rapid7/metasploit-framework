# coding: utf-8

class PDF::Reader

  # Takes a collection of TextRun objects and renders them into a single
  # string that best approximates the way they'd appear on a render PDF page.
  #
  # media box should be a 4 number array that describes the dimensions of the
  # page to be rendered as described by the page's MediaBox attribute
  class PageLayout

    DEFAULT_FONT_SIZE = 12

    def initialize(runs, mediabox)
      raise ArgumentError, "a mediabox must be provided" if mediabox.nil?

      @runs    = merge_runs(runs)
      @mean_font_size   = mean(@runs.map(&:font_size)) || DEFAULT_FONT_SIZE
      @mean_font_size = DEFAULT_FONT_SIZE if @mean_font_size == 0
      @mean_glyph_width = mean(@runs.map(&:mean_character_width)) || 0
      @page_width  = mediabox[2] - mediabox[0]
      @page_height = mediabox[3] - mediabox[1]
      @x_offset = @runs.map(&:x).sort.first
    end

    def to_s
      return "" if @runs.empty?

      page = row_count.times.map { |i| " " * col_count }
      @runs.each do |run|
        x_pos = ((run.x - @x_offset) / col_multiplier).round
        y_pos = row_count - (run.y / row_multiplier).round
        if y_pos <= row_count && y_pos >= 0 && x_pos <= col_count && x_pos >= 0
          local_string_insert(page[y_pos-1], run.text, x_pos)
        end
      end
      interesting_rows(page).map(&:rstrip).join("\n")
    end

    private

    # given an array of strings, return a new array with empty rows from the
    # beginning and end removed.
    #
    #   interesting_rows([ "", "one", "two", "" ])
    #   => [ "one", "two" ]
    #
    def interesting_rows(rows)
      line_lengths = rows.map { |l| l.strip.length }

      return [] if line_lengths.all?(&:zero?)

      first_line_with_text = line_lengths.index { |l| l > 0 }
      last_line_with_text  = line_lengths.size - line_lengths.reverse.index { |l| l > 0 }
      interesting_line_count = last_line_with_text - first_line_with_text
      rows[first_line_with_text, interesting_line_count].map
    end

    def row_count
      @row_count ||= (@page_height / @mean_font_size).floor
    end

    def col_count
      @col_count ||= ((@page_width  / @mean_glyph_width) * 1.05).floor
    end

    def row_multiplier
      @row_multiplier ||= @page_height.to_f / row_count.to_f
    end

    def col_multiplier
      @col_multiplier ||= @page_width.to_f / col_count.to_f
    end

    def mean(collection)
      if collection.size == 0
        0
      else
        collection.inject(0) { |accum, v| accum + v} / collection.size.to_f
      end
    end

    def each_line(&block)
      @runs.sort.group_by { |run|
        run.y.to_i
      }.map { |y, collection|
        yield y, collection
      }
    end

    # take a collection of TextRun objects and merge any that are in close
    # proximity
    def merge_runs(runs)
      runs.group_by { |char|
        char.y.to_i
      }.map { |y, chars|
        group_chars_into_runs(chars.sort)
      }.flatten.sort
    end

    def group_chars_into_runs(chars)
      runs = []
      while head = chars.shift
        if runs.empty?
          runs << head
        elsif runs.last.mergable?(head)
          runs[-1] = runs.last + head
        else
          runs << head
        end
      end
      runs
    end

    def local_string_insert(haystack, needle, index)
      haystack[Range.new(index, index + needle.length - 1)] = String.new(needle)
    end
  end
end
