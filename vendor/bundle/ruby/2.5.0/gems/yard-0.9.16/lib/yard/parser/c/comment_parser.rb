# frozen_string_literal: true
module YARD
  module Parser
    module C
      module CommentParser
        protected

        def parse_comments(comments)
          @overrides = []
          spaces = nil
          comments = remove_private_comments(comments)
          comments = comments.split(/\r?\n/).map do |line|
            line.gsub!(%r{^\s*/?\*/?}, '')
            line.gsub!(%r{\*/\s*$}, '')
            if line =~ /^\s*$/
              next if spaces.nil?
              next ""
            end
            spaces = (line[/^(\s+)/, 1] || "").size if spaces.nil?
            line.gsub(/^\s{0,#{spaces}}/, '').rstrip
          end.compact

          comments = parse_overrides(comments)
          comments = parse_callseq(comments)
          comments.join("\n")
        end

        private

        def parse_overrides(comments)
          comments.map do |line|
            type, name = *line.scan(/^\s*Document-(class|module|method|attr|const):\s*(\S.*)\s*$/).first
            if type
              @overrides << [type.to_sym, name]
              nil
            else
              line
            end
          end.compact
        end

        def parse_callseq(comments)
          return comments unless comments[0] =~ /\Acall-seq:\s*(\S.+)?/
          if $1
            comments[0] = " #{$1}"
          else
            comments.shift
          end
          overloads = []
          seen_data = false
          while comments.first =~ /^\s+(\S.+)/ || comments.first =~ /^\s*$/
            line = comments.shift.strip
            break if line.empty? && seen_data
            next if line.empty?
            seen_data = true
            line.sub!(/^\w+[\.#]/, '')
            signature, types = *line.split(/ [-=]> /)
            types = parse_types(types)
            if signature.sub!(/\[?\s*(\{(?:\s*\|(.+?)\|)?.*\})\s*\]?\s*$/, '') && $1
              blk = $1
              blkparams = $2
            else
              blk = nil
              blkparams = nil
            end
            case signature
            when /^(\w+)\s*=\s+(\w+)/
              signature = "#{$1}=(#{$2})"
            when /^\w+\s+\S/
              signature = signature.split(/\s+/)
              signature = "#{signature[1]}#{signature[2] ? '(' + signature[2..-1].join(' ') + ')' : ''}"
            when /^\w+\[(.+?)\]\s*(=)?/
              signature = "[]#{$2}(#{$1})"
            when /^\w+\s+(#{CodeObjects::METHODMATCH})\s+(\w+)/
              signature = "#{$1}(#{$2})"
            end
            break unless signature =~ /^#{CodeObjects::METHODNAMEMATCH}/
            signature = signature.rstrip
            overloads << "@overload #{signature}"
            overloads << "  @yield [#{blkparams}]" if blk
            overloads << "  @return [#{types.join(', ')}]" unless types.empty?
          end

          comments + [""] + overloads
        end

        def parse_types(types)
          if types =~ /true or false/
            ["Boolean"]
          else
            (types || "").split(/,| or /).map do |t|
              case t.strip.gsub(/^an?_/, '')
              when "class"; "Class"
              when "obj", "object", "anObject"; "Object"
              when "arr", "array", "anArray", "ary", "new_ary", /^\[/; "Array"
              when /^char\s*\*/, "char", "str", "string", "new_str"; "String"
              when "enum", "anEnumerator"; "Enumerator"
              when "exc", "exception"; "Exception"
              when "proc", "proc_obj", "prc"; "Proc"
              when "binding"; "Binding"
              when "hsh", "hash", "aHash"; "Hash"
              when "ios", "io"; "IO"
              when "file"; "File"
              when "float"; "Float"
              when "time", "new_time"; "Time"
              when "dir", "aDir"; "Dir"
              when "regexp", "new_regexp"; "Regexp"
              when "matchdata"; "MatchData"
              when "encoding"; "Encoding"
              when "fixnum", "fix"; "Fixnum"
              when /^(?:un)?signed$/, /^(?:(?:un)?signed\s*)?(?:short|int|long|long\s+long)$/, "integer", "Integer"; "Integer"
              when "num", "numeric", "Numeric", "number"; "Numeric"
              when "aBignum"; "Bignum"
              when "nil"; "nil"
              when "true"; "true"
              when "false"; "false"
              when "bool", "boolean", "Boolean"; "Boolean"
              when "self"; "self"
              when /^[-+]?\d/; t
              when /[A-Z][_a-z0-9]+/; t
              end
            end.compact
          end
        end

        def remove_private_comments(comment)
          comment = comment.gsub(%r{/?\*--\n(.*?)/?\*\+\+}m, '')
          comment = comment.sub(%r{/?\*--\n.*}m, '')
          comment
        end
      end
    end
  end
end
