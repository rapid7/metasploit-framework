#!/usr/bin/env ruby
# encoding: binary (rage)
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This scripts is used to compile the Metasm documentation into html files
# Losely inspired from the rst syntax

# stuff to generate html code
module Html
class Elem
  attr_reader :name, :attrs, :content, :style

  IndentAdd = '  '
  LineLenMax = 80
  
  def initialize(name, attrs=nil, content=nil)
    @name = name
    @attrs = Hash.new
    @style = Hash.new
    attrs.each { |k, v| set_attr(k, v) } if attrs
    if content == false
      @content = Array.new
      @uniq = true
    else
      @content = content ? content : Array.new
      @uniq = false
    end
    self
  end
  
  @@quotechars = {
    'è' => '&egrave;',
    'ë' => '&euml;',
    '>' => '&gt;',
    '<' => '&lt;',
    '"' => '&quot;',
    '&' => '&amp;',
  }
  
  def add(*content)
    content.each { |e|
      if (e.class == Array)
        add(*e)
        next
      end
      if e.class.ancestors.include? Elem
        @content << e
      else
        @content << e.to_s.gsub(Regexp.new("(#{@@quotechars.keys.join('|')})", 'm')) { |x| @@quotechars[x] }
      end
    }
    self
  end
  alias << add

  def add_style(k, v)
    @style[k] = v
    self
  end

  def set_attr(k, v)
    if k == 'style'
      v.split(/\s*;\s*/).each { |s|
        add_style($1, $2) if s =~ /^\s*(\S+)\s*:\s*(.*?)\s*$/
      }
    else
      @attrs[k]=v
    end
    self
  end

  def bg(c)
    @style['background'] = c
    self
  end
  
  def hclass(c)
    @attrs['class'] = c
    self
  end

  def length(start=nil)
    # text length on one line w/o indent
    if start
      l = start.length
    else
      # '<name>'
      l = @name.length + 2
      @attrs.each{ |k, v|
        l += " #{k}=\"#{v}\"".length
      }
      # ' style=""' - last '; '
      l += 9-2 unless @style.empty?
      # 'k: v; '
      @style.each{ |k, v|
        l += "#{k}: #{v}; ".length
      }
      # ' /'
      l += 2 if @uniq
    end
    @content.each{ |c|
      l += c.length
    }
    # '</name>'
    l += 3+@name.length unless @uniq
    return l
  end
  
  def to_s(indent = '')
    attrs = @attrs.map { |k, v| " #{k}=\"#{v}\"" }.join
    attrs += ' style="' + @style.map{ |k, v| "#{k}: #{v}" }.join('; ') + '"' unless @style.empty?
    s = '' << indent << '<' << @name << attrs << (@uniq ? ' />' : '>')
    if @uniq
      s
    elsif @name == 'pre'
      s << @content.map { |c| c.to_s }.join.chomp << '</pre>'
    else
      if length(s) > LineLenMax
        sindent = indent + IndentAdd
        sep = "\n"
        @content.each { |c|
          case c
          when Elem
            if sep == ''
              s << c.to_s(sindent).sub(/^\s+/, '')
            else
              news = c.to_s(sindent)
              plen = s.length - (s.rindex("\n") || -1) - 1
              plen -= 1 if s[-1, 1] == ' '
              newss = news.sub(/^\s+/, '')
              if not news.include?("\n") and s[-1] != ?> and
                  plen + 1 + newss.length <= LineLenMax
                # concat inline tag to previous String
                s << ' ' if s[-1, 1] != ' '
                s << newss
              else
                s << sep if c.name =~ /^h\d$/ and c != @content.first
                s << sep << news
              end
            end
          when String
            cw = c.split(/\s+/)
            if @name == 'p' and c.object_id == @content.first.object_id
              cw.shift if cw[0] == ''
              s << "\n" << sindent
            else
              s << cw.shift.to_s
            end
            plen = s.length - (s.rindex("\n") || -1) - 1
            while w = cw.shift
              plen -= 1 if s[-1, 1] == ' '
              if plen + 1 + w.length > LineLenMax
                s << "\n" << sindent
                plen = sindent.length
              end
              s << ' ' if s[-1, 1] != ' '
              s << w
              plen += w.length+1
            end
            if c !~ /\s+$/
              sep = ''
              next
            end
          else
            s << sep << sindent << c.to_s
          end
          sep = "\n"
        }
        sep = "\n" if @name == 'p'
        sep << indent if sep != ''
        s << sep << "</#@name>"
      else
        s << @content.map { |c| c.to_s }.join << "</#@name>"
      end
    end
  end

  def inspect
    "<#{@name}"+@content.map{|c|"\n"+c.inspect}.join+"\n/#{@name}>"
  end
end	

class Page < Elem
  attr_reader :body, :head
  def initialize
    @body = Elem.new('body')
    @head = Elem.new('head')
    super('html', {'xmlns'=>'http://www.w3.org/1999/xhtml', 'xml:lang'=>'fr'})
    add(@head)
    add(@body)
  end

  def to_s
    '<?xml version="1.0" encoding="us-ascii" ?>'+"\n"+
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"'+"\n"+
    IndentAdd*2+'"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'+"\n"+
    super.to_s
  end
end
class Img < Elem
  def initialize(src, alt=nil)
    super('img', {'src'=>src}, false)
    set_attr('alt', alt) if alt
    self
  end
end
class A < Elem
  def initialize(href, text)
    super('a', {'href'=>href}, [text])
  end
end
class P < Elem
  def initialize(content = nil)
    super('p')
    add(content) if content
    self
  end
end
class Div < Elem
  def initialize(hclass = nil)
    super('div')
    hclass(hclass) if hclass
    self
  end
end
class Span < Elem
  def initialize(hclass = nil)
    super('span')
    hclass(hclass) if hclass
    self
  end
end
class Stylesheet < Elem
  def initialize(href)
    super('link', {'rel'=>'stylesheet', 'type'=>'text/css', 'href'=>href}, false)
  end
end
class Br < Elem
  def initialize
    super('br', nil, false)
  end
end
class Hr < Elem
  def initialize
    super('hr', nil, false)
  end
end

class List < Elem
  def initialize(*elems)
    super('ul')
    elems.each { |e| add_line(e) }
  end

  def add_line(line)
    add(Elem.new('li').add(line))
    self
  end
end
end

class Txt2Html
  def initialize(f)
    @@done ||= []
    return if @@done.include? f
    @@done << f

    raise 'bad path' if (f.split('/') & ['.', '..']).first

    outf = outfilename(f)
    puts "compiling #{outf}..." if $VERBOSE

    @pathfix = outf.split('/')[0...-1].map { '../' }.join
    out = compile(File.open(f, 'rb') { |fd| fd.read }.gsub("\r", '') + "\n\n")
    File.open(outf, 'wb') { |fd| fd.write out.to_s.gsub("\r", '').gsub("\n", "\r\n") }
  end

  def outfilename(f)
    f.sub(/\.txt$/, '') + '.html'
  end

  def compile(raw)
    prev = ''
    state = {}
    anchors = {}
    out = Html::Page.new
    out.head << Html::Stylesheet.new(@pathfix + 'style.css')
    flush = lambda {
      out.body << Html::P.new(compile_string(prev)) if prev.length > 0
      [:pre, :list, :par].each { |f| state.delete f }
      prev = ''
    }
    raw.each_line { |l|
      case l = l.chomp
      when /^([=#*-])\1{3,}$/
        if prev.length > 0
          # title
          if    not state[:h1] or state[:h1] == $1
            state[:h1] = $1
            e = 'h1'
          elsif not state[:h2] or state[:h2] == $1
            state[:h2] = $1
            e = 'h2'
          elsif not state[:h3] or state[:h3] == $1
            state[:h3] = $1
            e = 'h3'
          else raise "unknown title level after #{prev.inspect}"
          end
          str = compile_string(prev)
          state[:title] ||= str if e == 'h1'
          if id = prev[/[a-z]\w+/i]
            id = id.downcase
            id += '_' while anchors[id]
            anchors[id] = true
            attr = { 'id' => id }
          end
          out.body << Html::Elem.new(e, attr).add(str)
          prev = ''
          flush[]
        else
          # horizontal rule
          out.body << Html::Hr.new
          flush[]
        end
      when /^([*-]+)\s+(.*)/
        # list
        bullet = $1
        text = $2
        if lst = state[:list] && state[:list][bullet]
          state[:list].delete_if { |k, v| k.length > bullet.length }
        else
          flush[] if not state[:list]
          state[:list] ||= {}
          state[:list].delete_if { |k, v| k.length > bullet.length }
          lst = state[:list][bullet] = Html::List.new
          if pl = state[:list][bullet.chop]
            pl.content.last.content << lst
          else
            out.body << lst
          end
        end
        lst.add_line compile_string(text)

      when /^\s+(\S.*)$/
        # preformatted text
        if not pre = state[:pre]
          flush[]
          pre = state[:pre] = Html::Elem.new('pre')
          out.body << pre
        end
        pre.add compile_string(l) + ["\n"]
      when /^\s*$/
        flush[]
      else
        if state[:list]
          lst = state[:list].sort.last[1]
          lst.content.last.content << ' ' << compile_string(l)
        else
          prev << ' ' if prev.length > 0
          prev << l
        end
      end
    }
    flush[]
    out.head << Html::Elem.new('title').add(state[:title]) if state[:title]
    out
  end

  # handle **bold_words** *italic* `fixed` <links> **bold__word__with__underscore**
  def compile_string(str)
    o = [str]
    on = []
    o.each { |s|
      while s.kind_of? String and o1 = s.index('**') and o2 = s.index('**', o1+2) and not s[o1..o2].index(' ')
        on << s[0...o1] << Html::Elem.new('b').add(s[o1+2...o2].tr('_', ' ').gsub('  ', '_'))
        s = s[o2+2..-1]
      end
      on << s
    }
    o = on
    on = []
    o.each { |s|
      while s.kind_of? String and o1 = s.index('*') and o2 = s.index('*', o1+1) and not s[o1..o2].index(' ')
        on << s[0...o1] << Html::Elem.new('i').add(s[o1+1...o2].tr('_', ' ').gsub('  ', '_'))
        s = s[o2+1..-1]
      end
      on << s
    }
    o = on
    on = []
    o.each { |s|
      while s.kind_of? String and o1 = s.index('`') and o2 = s.index('`', o1+1)
        on << s[0...o1] << Html::Span.new('quote').add(s[o1+1...o2])
        s = s[o2+1..-1]
      end
      on << s
    }
    o = on
    on = []
    o.each { |s|
      while s.kind_of? String and o1 = s.index('<') and o2 = s.index('>', o1+1) and not s[o1..o2].index(' ')
        on << s[0...o1]
        lnk = s[o1+1...o2]
        s = s[o2+1..-1]
        if File.exist? lnk
          case lnk[/\.(\w+)$/, 1]
          when 'txt'
            tg = outfilename(lnk)
            Txt2Html.new(lnk)
            on << Html::A.new(@pathfix + tg, File.basename(lnk, '.txt').tr('_', ' ').gsub('  ', '_'))
          when 'jpg', 'png'
            on << Html::Img.new(lnk)
          end
        else
          on << Html::A.new(lnk, lnk)
          if lnk =~ /\.txt$/
            @@seen_nofile ||= []
            if not @@seen_nofile.include? lnk
              @@seen_nofile << lnk
              puts "reference to missing #{lnk.inspect}"
            end
            on.last.hclass('brokenlink')
          end
        end
      end
      on << s
    }
    o = on
  end
end

if __FILE__ == $0
  $VERBOSE = true if ARGV.delete '-v'
  if ARGV.empty?
    Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '../doc')))
    ARGV.concat Dir['**/index.txt']
  end
  ARGV.each { |a| Txt2Html.new(a) }
end
