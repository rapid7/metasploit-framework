#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# This sample implements a trivial binary diffing algorithm between two programs
# the programs have first to be disassembled, and then the diff algorith will
# (try to) identify identical functions in both dasm graphs
# Currently there is NO fuzzy matching whatsoever, so the function graphs have to
# be exactly the same in both programs to be recognized.
# You can still force a comparaison between two functions, but the results will be bad.
#
# This file can be run as a standalone application (eg 'ruby bindiff file1 file2')
# or as a disassembler plugin (see dasm-plugin/bindiff)

require 'metasm'

module ::Metasm
class BinDiffWidget < Gui::DrawableWidget
  attr_accessor :status

  COLORS = { :same => '8f8', :similar => 'cfc', :badarg => 'fcc', :badop => 'faa', :default => '888' }

  def initialize_widget(d1=nil, d2=nil)
    self.dasm1 = d1 if d1
    self.dasm2 = d2 if d2
    @status = nil
  end

  def dasm1; @dasm1 end
  def dasm1=(d)
    @dasm1 = d
    @func1 = nil
    @funcstat1 = nil
    @dasmcol1 = {}
    @dasm1.gui.bg_color_callback = lambda { |a1| COLORS[@dasmcol1[a1] || :default] }
    @match_func = nil
  end

  def dasm2; @dasm2 end
  def dasm2=(d)
    @dasm2 = d
    @func2 = nil
    @funcstat1 = nil
    @dasmcol2 = {}
    @dasm2.gui.bg_color_callback = lambda { |a2| COLORS[@dasmcol2[a2] || :default] }
    @match_func = nil
  end

  def curaddr1; @dasm1.gui.curaddr end
  def curaddr2; @dasm2.gui.curaddr end
  def curfunc1; @dasm1.find_function_start(curaddr1) end
  def curfunc2; @dasm2.find_function_start(curaddr2) end
  def func1; @func1 ||= set_status('funcs 1') { create_funcs(@dasm1) } end
  def func2; @func2 ||= set_status('funcs 2') { create_funcs(@dasm2) } end
  def funcstat1; @funcstat1 ||= set_status('func stats 1') { create_funcs_stats(func1, @dasm1) } end
  def funcstat2; @funcstat2 ||= set_status('func stats 2') { create_funcs_stats(func2, @dasm2) } end

  def paint
    draw_string_color(:black, @font_width, 3*@font_height, @status || 'idle')
  end

  def gui_update
    @dasm1.gui.gui_update rescue nil
    @dasm2.gui.gui_update rescue nil
    redraw
  end

  def set_status(st=nil)
    ost = @status
    @status = st
    redraw
    if block_given?
      ret = protect { yield }
      set_status ost
      ret
    end
  end

  def keypress(key)
    case key
    when ?A
      keypress(?D)
      keypress(?f)
      keypress(?i)
    when ?D
      disassemble_all
    when ?c
      disassemble
    when ?C
      disassemble(:disassemble_fast)
    when ?f
      funcstat1
      funcstat2
    when ?g
      inputbox('address to go', :text => Expression[@dasm1.gui.curaddr]) { |v|
        @dasm1.gui.focus_addr_autocomplete(v)
        @dasm2.gui.focus_addr_autocomplete(v)
      }
    when ?M
      show_match_funcs
    when ?m
      match_one_func(curfunc1, curfunc2)

    when ?r
      puts 'reload'
      load __FILE__
      gui_update

    when ?Q
      Gui.main_quit
    end
  end

  def keypress_ctrl(key)
    case key
    when ?C
      disassemble(:disassemble_fast_deep)
    when ?r
      inputbox('code to eval') { |c| messagebox eval(c).inspect[0, 512], 'eval' }
    end
  end

  def disassemble_all
    @func1 = @func2 = @funcstat1 = @funcstat2 = nil
    @dasm1.load_plugin 'dasm_all'
    @dasm2.load_plugin 'dasm_all'
    set_status('dasm_all 1') { @dasm1.dasm_all_section '.text' }
    set_status('dasm_all 2') { @dasm2.dasm_all_section '.text' }
    gui_update
  end

  def disassemble(method=:disassemble)
    @func1 = @func2 = @funcstat1 = @funcstat2 = nil
    set_status('dasm 1') {
      @dasm1.send(method, curaddr1)
      @dasm1.gui.focus_addr(curaddr1, :graph)
    }
    set_status('dasm 2') {
      @dasm2.send(method, curaddr2)
      @dasm2.gui.focus_addr(curaddr2, :graph)
    }
    gui_update
  end


  def show_match_funcs
    match_funcs

    gui_update
    Gui.main_iter
    list = [['addr 1', 'addr 2', 'score']]
    f1 = func1.keys
    f2 = func2.keys
    match_funcs.each { |a1, (a2, s)|
      list << [(@dasm1.get_label_at(a1) || Expression[a1]), (@dasm2.get_label_at(a2) || Expression[a2]), '%.4f' % s]
      f1.delete a1
      f2.delete a2
    }
    f1.each { |a1| list << [(@dasm1.get_label_at(a1) || Expression[a1]), '?', 'nomatch'] }
    f2.each { |a2| list << ['?', (@dasm2.get_label_at(a2) || Expression[a2]), 'nomatch'] }
    listwindow("matches", list) { |i| @dasm1.gui.focus_addr i[0], nil, true ; @dasm2.gui.focus_addr i[1], nil, true }
  end

  # func addr => { funcblock => list of funcblock to }
  def create_funcs(dasm)
    f = {}
    dasm.entrypoints.to_a.each { |ep| dasm.function[ep] ||= DecodedFunction.new }
    dasm.function.each_key { |a|
      next if not dasm.di_at(a)
      f[a] = create_func(dasm, a)
      Gui.main_iter
    }
    f
  end

  def create_func(dasm, a)
    h = {}
    todo = [a]
    while a = todo.pop
      next if h[a]
      h[a] = []
      dasm.decoded[a].block.each_to_samefunc(dasm) { |ta|
        next if not dasm.di_at(ta)
        todo << ta
        h[a] << ta
      }
    end
    h
  end

  def create_funcs_stats(f, dasm)
    fs = {}
    f.each { |a, g|
      fs[a] = create_func_stats(dasm, a, g)
      Gui.main_iter
    }
    fs
  end

  def create_func_stats(dasm, a, g)
    s = {}
    s[:blocks] = g.length

    s[:edges] = 0	# nr of edges
    s[:leaves] = 0	# nr of nodes with no successor
    s[:ext_calls] = 0	# nr of jumps out_of_func
    s[:loops] = 0	# nr of jump back

    todo = [a]
    done = []
    while aa = todo.pop
      next if done.include? aa
      done << aa
      todo.concat g[aa]

      s[:edges] += g[aa].length
      s[:leaves] += 1 if g[aa].empty?
      dasm.decoded[aa].block.each_to_otherfunc(dasm) { s[:ext_calls] += 1 }
    end

    # loop detection
    # find the longest distance to the root w/o loops
    g = g.dup
    while eliminate_one_loop(a, g)
      s[:loops] += 1
    end

    s
  end

  def eliminate_one_loop(a, g)
    stack = []
    index = {}
    reach_index = {}
    done = false

    curindex = 0
    
    trajan = lambda { |e|
      index[e] = curindex
      reach_index[e] = curindex
      curindex += 1
      stack << e
      g[e].each { |ne|
        if not index[ne]
          trajan[ne]
          break if done
          reach_index[e] = [reach_index[e], reach_index[ne]].min
        elsif stack.include? ne
          reach_index[e] = [reach_index[e], reach_index[ne]].min
        end
      }
      break if done
      if index[e] == reach_index[e]
        if (e == stack.last and not g[e].include? e)
          stack.pop
          next
        end
        # e is the entry in the loop, cut the loop here
        tail = reach_index.keys.find { |ee| reach_index[ee] == index[e] and g[ee].include? e }
        g[tail] -= [e]	# patch g, but don't modify the original g value (ie -= instead of delete)
        done = true	# one loop found & removed, try again
      end
    }

    trajan[a]
    done
  end

  def rematch_funcs
    @match_funcs = nil
    match_funcs
  end

  def match_funcs
    @match_funcs ||= {}

    layout_match = {}

    set_status('match func layout') {
    funcstat1.each { |a, s|
      next if @match_funcs[a]
      layout_match[a] = []
      funcstat2.each { |aa, ss|
        layout_match[a] << aa if s == ss
      }
      Gui.main_iter
    }
    }

    set_status('match funcs') {
    # refine the layout matching with actual function matching
    already_matched = []
    match_score = {}
    layout_match.each { |f1, list|
puts "matching #{Expression[f1]}" if $VERBOSE
begin
      f2 = (list - already_matched).sort_by { |f| match_func(f1, f, false, false) }.first
      if f2
        already_matched << f2
        score = match_func(f1, f2)
        @match_funcs[f1] = [f2, score]
      end
rescue Interrupt
  puts 'abort this one'
  sleep 0.2	# allow a 2nd ^c do escalate
end
      Gui.main_iter
    }
    }

    puts "matched #{@match_funcs.length} - unmatched #{func1.length - @match_funcs.length}"
    @match_funcs
  end

  def match_one_func(a1, a2)
    s = match_func(a1, a2)
    puts "match score: #{s}"
    @match_funcs ||= {}
    @match_funcs[a1] = [a2, s]
    gui_update
  end

  # return how much match a func in d1 and a func in d2
  def match_func(a1, a2, do_colorize=true, verb=true)
    f1 = func1[a1]
    f2 = func2[a2]
    raise "dasm1 has no function at #{Expression[a1]}" if not f1
    raise "dasm2 has no function at #{Expression[a2]}" if not f2
    todo1 = [a1]
    todo2 = [a2]
    done1 = []
    done2 = []
    score = 0.0	# average of the (local best) match_block scores
    score += 0.01 if @dasm1.get_label_at(a1) != @dasm2.get_label_at(a2)	# for thunks
    score_div = [f1.length, f2.length].max.to_f
    # XXX this is stupid and only good for perfect matches (and even then it may fail)
    # TODO handle block split etc (eg instr-level diff VS block-level)
    while a1 = todo1.shift
      next if done1.include? a1
      t = todo2.map { |a| [a, match_block(@dasm1.decoded[a1].block, @dasm2.decoded[a].block)] }
      a2 = t.sort_by { |a, s| s }.first
      if not a2
        break
      end
      score += a2[1] / score_div
      a2 = a2[0]
      done1 << a1
      done2 << a2
      todo1.concat f1[a1]
      todo2.concat f2[a2]
      todo2 -= done2
      colorize_blocks(a1, a2) if do_colorize
    end

    score += (f1.length - f2.length).abs * 3 / score_div	# block count difference -> +3 per block

    score
  end

  def match_block(b1, b2)
    # 0 = perfect match (same opcodes, same args)
    # 1 = same opcodes, same arg type
    # 2 = same opcodes, diff argtypes
    # 3 = some opcode difference
    # 4 = full block difference
    score = 0
    score_div = [b1.list.length, b2.list.length].max.to_f
    common_start = 0
    common_end = 0

    # basic diff-style: compare start while it's good, then end, then whats left
    # should handle most simples cases well
    len = [b1.list.length, b2.list.length].min
    while common_start < len and (s = match_instr(b1.list[common_start], b2.list[common_start])) <= 1
      score += s / score_div
      common_start += 1
    end

    while common_start+common_end < len and (s = match_instr(b1.list[-1-common_end], b2.list[-1-common_end])) <= 1
      score += s / score_div
      common_end += 1
    end

    # TODO improve the middle part matching (allow insertions/suppressions/swapping)
    b1.list[common_start..-1-common_end].zip(b2.list[common_start..-1-common_end]).each { |di1, di2|
      score += match_instr(di1, di2) / score_div
    }

    yield(common_start, common_end) if block_given?	# used by colorize_blocks

    score += (b1.list.length - b2.list.length).abs * 3 / score_div	# instr count difference -> +3 per instr

    score
  end

  def colorize_blocks(a1, a2)
    b1 = @dasm1.decoded[a1].block
    b2 = @dasm2.decoded[a2].block

    common_start = common_end = 0
    match_block(b1, b2) { |a, b| common_start = a ; common_end = b }

    b1.list[0..-1-common_end].zip(b2.list[0..-1-common_end]).each { |di1, di2|
      next if not di1 or not di2
      @dasmcol1[di1.address] = @dasmcol2[di2.address] = [:same, :similar, :badarg, :badop][match_instr(di1, di2)]
    }
    b1.list[-common_end..-1].zip(b2.list[-common_end..-1]).each { |di1, di2|
      next if not di1 or not di2
      @dasmcol1[di1.address] = @dasmcol2[di2.address] = [:same, :similar, :badarg, :badop][match_instr(di1, di2)]
    }
  end

  def match_instr(di1, di2)
    if not di1 or not di2 or di1.opcode.name != di2.opcode.name
      3
    elsif di1.instruction.args.map { |a| a.class } != di2.instruction.args.map { |a| a.class }
      2
    elsif di1.instruction.to_s.gsub(/loc_\w+/, 'loc_') != di2.instruction.to_s.gsub(/loc_\w+/, 'loc_')	# local labels	 TODO compare blocks targeted
      1
    else
      0
    end
  end

  # show in window 1 the match of the function found in win 2
  def sync1
    c2 = curfunc2
    if a1 = match_funcs.find { |k, (a2, s)| a2 == c2 }
      @dasm1.gui.focus_addr(a1[0])
    end
  end

  def sync2
    if a2 = match_funcs[curfunc1]
      @dasm2.gui.focus_addr(a2[0])
    end
  end
end

class BinDiffWindow < Gui::Window
  def initialize_window(d1=nil, d2=nil)
    self.widget = BinDiffWidget.new(d1, d2)
  end

  def build_menu
    menu = new_menu
    addsubmenu(menu, 'load file 1') { openfile('file 1') { |f| loadfile1(f) } }
    addsubmenu(menu, 'load file 2') { openfile('file 2') { |f| loadfile2(f) } }
    addsubmenu(menu)
    addsubmenu(menu, '_disassemble from there', '^C') { widget.disassemble(:disassemble_fast_deep) }
    addsubmenu(menu, 'co_mpare current functions', 'm') { widget.match_one_func(widget.curfunc1, widget.curfunc2) }
    addsubmenu(menu, 'compare all funct_ions', 'M') { widget.show_match_funcs }
    addsubmenu(menu, '_goto', 'g') { widget.keypress ?g }
    addsubmenu(menu)
    addsubmenu(menu, 'sync win 2', '2') { widget.sync2 }
    addsubmenu(menu, 'sync win 1', '1') { widget.sync1 }
    addsubmenu(menu)
    addsubmenu(menu, '_quit', 'Q') { Gui.main_quit }

    addsubmenu(@menu, '_File', menu)
  end

  def loadfile1(f)
    exe = AutoExe.orshellcode { Ia32.new }.decode_file(f)
    d = exe.init_disassembler
    Gui::DasmWindow.new("bindiff - 1 - #{f}").display(d)
    widget.dasm1 = d
  end

  def loadfile2(f)
    exe = AutoExe.orshellcode { Ia32.new }.decode_file(f)
    d = exe.init_disassembler
    Gui::DasmWindow.new("bindiff - 2 - #{f}").display(d)
    widget.dasm2 = d
  end
end
end

if $0 == __FILE__ and not defined? $bindiff_loaded
# allow reloading the file for easier diff algorithm test
$bindiff_loaded = true

require 'optparse'

$VERBOSE = true

# parse arguments
opts = {}
OptionParser.new { |opt|
  opt.banner = 'Usage: bindiff.rb [options] <executable> [<entrypoints>]'
  opt.on('-P <plugin>', '--plugin <plugin>', 'load a metasm disassembler plugin') { |h| (opts[:plugin] ||= []) << h }
  opt.on('-e <code>', '--eval <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
  opt.on('--map1 <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map1] = f }
  opt.on('--map2 <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map2] = f }
  opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
  opt.on('-a', '--autoload', 'loads all relevant files with same filename (.h, .map..)') { opts[:autoload] = true }
  opt.on('-v', '--verbose') { $VERBOSE = true }	# default
  opt.on('-q', '--no-verbose') { $VERBOSE = false }
  opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
  opt.on('-A', 'match everything on start') { opts[:doit] = true }
}.parse!(ARGV)

if exename1 = ARGV.shift
  w1 = Metasm::Gui::DasmWindow.new("#{exename1} - bindiff1 - metasm disassembler")
  exe1 = w1.loadfile(exename1)
  if opts[:autoload]
    basename1 = exename1.sub(/\.\w\w?\w?$/, '')
    opts[:map1] ||= basename1 + '.map' if File.exist?(basename1 + '.map')
    opts[:cheader] ||= basename1 + '.h' if File.exist?(basename1 + '.h')
  end
end

if exename2 = ARGV.shift
  w2 = Metasm::Gui::DasmWindow.new("#{exename2} - bindiff2 - metasm disassembler")
  exe2 = w2.loadfile(exename2)
  if opts[:autoload]
    basename2 = exename2.sub(/\.\w\w?\w?$/, '')
    opts[:map2] ||= basename2 + '.map' if File.exist?(basename2 + '.map')
    opts[:cheader] ||= basename2 + '.h' if File.exist?(basename2 + '.h')
  end
end

if exe1
  dasm1 = exe1.init_disassembler
  dasm1.load_map opts[:map1] if opts[:map1]
  dasm1.parse_c_file opts[:cheader] if opts[:cheader]
end

if exe2
  dasm2 = exe2.init_disassembler
  dasm2.load_map opts[:map2] if opts[:map2]
  dasm2.parse_c_file opts[:cheader] if opts[:cheader]
end

ep = ARGV.dup

w1.dasm_widget.focus_addr ep.first if w1 and not ep.empty?
w2.dasm_widget.focus_addr ep.first if w2 and not ep.empty?

opts[:plugin].to_a.each { |p| dasm1.load_plugin(p) if dasm1 ; dasm2.load_plugin(p) if dasm2 }
opts[:hookstr].to_a.each { |f| eval f }

ep.each { |e| dasm1.disassemble_fast_deep(e) if dasm1 ; dasm2.disassemble_fast_deep(e) if dasm2 }

bd = Metasm::BinDiffWindow.new(dasm1, dasm2)

bd.widget.keypress ?A if opts[:doit]

Metasm::Gui.main

end
