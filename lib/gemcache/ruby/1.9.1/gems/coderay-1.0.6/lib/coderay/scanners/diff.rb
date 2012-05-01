module CodeRay
module Scanners
  
  # Scanner for output of the diff command.
  # 
  # Alias: +patch+
  class Diff < Scanner
    
    register_for :diff
    title 'diff output'
    
    DEFAULT_OPTIONS = {
      :highlight_code => true,
      :inline_diff    => true,
    }
    
  protected
    
    def scan_tokens encoder, options
      
      line_kind = nil
      state = :initial
      deleted_lines = 0
      scanners = Hash.new do |h, lang|
        h[lang] = Scanners[lang].new '', :keep_tokens => true, :keep_state => true
      end
      content_scanner = scanners[:plain]
      content_scanner_entry_state = nil
      
      until eos?
        
        if match = scan(/\n/)
          deleted_lines = 0 unless line_kind == :delete
          if line_kind
            encoder.end_line line_kind
            line_kind = nil
          end
          encoder.text_token match, :space
          next
        end
        
        case state
        
        when :initial
          if match = scan(/--- |\+\+\+ |=+|_+/)
            encoder.begin_line line_kind = :head
            encoder.text_token match, :head
            if match = scan(/.*?(?=$|[\t\n\x00]|  \(revision)/)
              encoder.text_token match, :filename
              if options[:highlight_code] && match != '/dev/null'
                file_type = CodeRay::FileType.fetch(match, :text)
                file_type = :text if file_type == :diff
                content_scanner = scanners[file_type]
                content_scanner_entry_state = nil
              end
            end
            next unless match = scan(/.+/)
            encoder.text_token match, :plain
          elsif match = scan(/Index: |Property changes on: /)
            encoder.begin_line line_kind = :head
            encoder.text_token match, :head
            next unless match = scan(/.+/)
            encoder.text_token match, :plain
          elsif match = scan(/Added: /)
            encoder.begin_line line_kind = :head
            encoder.text_token match, :head
            next unless match = scan(/.+/)
            encoder.text_token match, :plain
            state = :added
          elsif match = scan(/\\ .*/)
            encoder.text_token match, :comment
          elsif match = scan(/@@(?>[^@\n]*)@@/)
            content_scanner.state = :initial unless match?(/\n\+/)
            content_scanner_entry_state = nil
            if check(/\n|$/)
              encoder.begin_line line_kind = :change
            else
              encoder.begin_group :change
            end
            encoder.text_token match[0,2], :change
            encoder.text_token match[2...-2], :plain
            encoder.text_token match[-2,2], :change
            encoder.end_group :change unless line_kind
            next unless match = scan(/.+/)
            if options[:highlight_code]
              content_scanner.tokenize match, :tokens => encoder
            else
              encoder.text_token match, :plain
            end
            next
          elsif match = scan(/\+/)
            encoder.begin_line line_kind = :insert
            encoder.text_token match, :insert
            next unless match = scan(/.+/)
            if options[:highlight_code]
              content_scanner.tokenize match, :tokens => encoder
            else
              encoder.text_token match, :plain
            end
            next
          elsif match = scan(/-/)
            deleted_lines += 1
            encoder.begin_line line_kind = :delete
            encoder.text_token match, :delete
            if options[:inline_diff] && deleted_lines == 1 && check(/(?>.*)\n\+(?>.*)$(?!\n\+)/)
              content_scanner_entry_state = content_scanner.state
              skip(/(.*)\n\+(.*)$/)
              head, deletion, insertion, tail = diff self[1], self[2]
              pre, deleted, post = content_scanner.tokenize [head, deletion, tail], :tokens => Tokens.new
              encoder.tokens pre
              unless deleted.empty?
                encoder.begin_group :eyecatcher
                encoder.tokens deleted
                encoder.end_group :eyecatcher
              end
              encoder.tokens post
              encoder.end_line line_kind
              encoder.text_token "\n", :space
              encoder.begin_line line_kind = :insert
              encoder.text_token '+', :insert
              content_scanner.state = content_scanner_entry_state || :initial
              pre, inserted, post = content_scanner.tokenize [head, insertion, tail], :tokens => Tokens.new
              encoder.tokens pre
              unless inserted.empty?
                encoder.begin_group :eyecatcher
                encoder.tokens inserted
                encoder.end_group :eyecatcher
              end
              encoder.tokens post
            elsif match = scan(/.*/)
              if options[:highlight_code]
                if deleted_lines == 1
                  content_scanner_entry_state = content_scanner.state
                end
                content_scanner.tokenize match, :tokens => encoder unless match.empty?
                if !match?(/\n-/)
                  if match?(/\n\+/)
                    content_scanner.state = content_scanner_entry_state || :initial
                  end
                  content_scanner_entry_state = nil
                end
              else
                encoder.text_token match, :plain
              end
            end
            next
          elsif match = scan(/ .*/)
            if options[:highlight_code]
              content_scanner.tokenize match, :tokens => encoder
            else
              encoder.text_token match, :plain
            end
            next
          elsif match = scan(/.+/)
            encoder.begin_line line_kind = :comment
            encoder.text_token match, :plain
          else
            raise_inspect 'else case rached'
          end
        
        when :added
          if match = scan(/   \+/)
            encoder.begin_line line_kind = :insert
            encoder.text_token match, :insert
            next unless match = scan(/.+/)
            encoder.text_token match, :plain
          else
            state = :initial
            next
          end
        end
        
      end
      
      encoder.end_line line_kind if line_kind
      
      encoder
    end
    
  private
    
    def diff a, b
      # i will be the index of the leftmost difference from the left.
      i_max = [a.size, b.size].min
      i = 0
      i += 1 while i < i_max && a[i] == b[i]
      # j_min will be the index of the leftmost difference from the right.
      j_min = i - i_max
      # j will be the index of the rightmost difference from the right which
      # does not precede the leftmost one from the left.
      j = -1
      j -= 1 while j >= j_min && a[j] == b[j]
      return a[0...i], a[i..j], b[i..j], (j < -1) ? a[j+1..-1] : ''
    end
    
  end
  
end
end
