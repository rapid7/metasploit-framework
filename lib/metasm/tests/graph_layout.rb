#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# special file to test the graph layout engine
# call this file directly to run

require 'metasm'
include Metasm

def test_layout(lo)
  $cur ||= 0
  $cur += 1
  if $target.to_i != 0
    return if $cur != $target
  else
    return if not lo.include? $target
  end if $target
  puts $cur, lo, '' if $VERBOSE
  w = Gui::Window.new
  ww = w.widget = Gui::GraphViewWidget.new(nil, nil)
  ww.grab_focus
  Gui.idle_add {
    ww.load_dot(lo)
    ww.curcontext.auto_arrange_boxes
    ww.zoom_all
    false
  }
  Gui.main
end

def test_all
  test_layout <<EOS
line -> 2 -> 3 -> 4 -> 5 -> 6 -> 7;
EOS
  test_layout <<EOS
sep1 -> 1;
sep2 -> 2;
sep3 -> 3;
sep4 -> 4;
sep5 -> 5;
EOS
  test_layout <<EOS
fork -> 2 -> 3;
2 -> 4;
EOS
  test_layout <<EOS
diamond -> 2 -> 3 -> 5;
2 -> 4 -> 5;
EOS
  test_layout <<EOS
ifthen -> 2 -> 3 -> 4;
2 -> 4;
EOS
  test_layout <<EOS
ufork -> 2 -> 3;
1 -> 2;
EOS
  test_layout <<EOS
multidiamond -> 2 -> 31 -> 32 -> 34 -> 5 -> 6 -> 8;
2 -> 41 -> 42 -> 44 -> 5 -> 7 -> 8;
41 -> 43 -> 44;
31 -> 33 -> 34;
EOS
  test_layout <<EOS
dmdout -> 2 -> 3a -> 4;
2 -> 3b -> 4;
3a -> 4a;
3b -> 4b;
EOS
  test_layout <<EOS
ifthenthen -> 2 -> 8;
2 -> 3 -> 8;
2 -> 4 -> 5 -> 8;
2 -> 6 -> 7 -> 8;
EOS
  test_layout <<EOS
multipod -> 2 -> 3;
2 -> 4;
2 -> 5;
2 -> 6;
2 -> 7;
2 -> 8;
EOS
  test_layout <<EOS
mplarge -> 1 -> 2;
1 -> 3333333333333333333333333333333333;
EOS
  test_layout <<EOS
multif -> 1
1 -> a2 -> a3
a2 -> a222222222 -> a3
1 -> b2 -> b3
b2 -> b222222222 -> b3
EOS
  test_layout <<EOS
ifx -> 1 -> 2 -> 3 -> 4 -> 5
4 -> eeeeeeeeeeee -> 5
EOS
  test_layout <<EOS
llll -> 1 -> 22222222222222222222222222 -> e
1 -> 33333333333333333333333333 -> e
1 -> 4444444444444444444444 -> e
1 -> 5 -> e
5 -> 5t -> e
1 -> 6 -> e
6 -> 6t -> e
1 -> 7 -> e
7 -> 7t -> e
EOS
  test_layout <<EOS
dangling -> 2 -> 11 -> 12 -> 13 -> 4;
2 -> 21 -> 22 -> 23 -> 4;
2 -> 31 -> 32 -> 33 -> 4;
21 -> 2z;
31 -> 3z;
EOS
  test_layout <<EOS
dangin -> 2 -> 11 -> 12 -> 13;
2 -> 21 -> 22 -> 13;
2 -> 31 -> 32 -> 33;
22 -> 33;
21 -> z;
EOS
  test_layout <<EOS
cascadeclean -> 2 -> 3 -> 4 -> 5 -> 6 -> 62 -> 52 -> 42 -> 32 -> 22 -> e;
2 -> 21 -> 22;
3 -> 31 -> 32;
4 -> 41 -> 42;
5 -> 51 -> 52;
6 -> 61 -> 62;
EOS
  test_layout <<EOS
cascade -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> e;
2 -> 21 -> e;
3 -> 31 -> e;
4 -> 41 -> e;
5 -> 51 -> e;
6 -> 61 -> e;
EOS
  test_layout <<EOS
rstair -> 2 -> 3 -> 4 -> 5 -> 6;
2 -> 4;
2 -> 5;
2 -> 6;
EOS
  test_layout <<EOS
drstair -> 2a -> 3 -> 4 -> 5 -> 6;
drstair -> 2b -> 4;
2a -> 4;
2a -> 5;
2a -> 6;
2b -> 4;
2b -> 5;
2b -> 6;
EOS
  test_layout <<EOS
mrstair -> 2a -> 3a -> 4a -> 5a -> 6a;
mrstair -> 2b -> 4a;
2a -> 4a;
2a -> 5a;
2a -> 6a;
2b -> 4a;
2b -> 5a;
2b -> 6a;
2a -> 3b -> 4b -> 5b -> 6b;
2a -> 4b;
2a -> 5b;
2a -> 6b;
2b -> 3b;
2b -> 4b;
2b -> 5b;
2b -> 6b;
EOS
  test_layout <<EOS
loop -> 2 -> 3 -> 4;
3 -> 2;
EOS
  test_layout <<EOS
loopbreak -> 2 -> 3 -> e;
2 -> 4 -> 5 -> 6 -> 8 -> e;
5 -> 7 -> 4;
EOS
  test_layout <<EOS
loopbreak2 -> 2 -> 3 -> e;
2 -> 4 -> 5 -> 6 -> 8 -> e;
5 -> 7 -> 4;
7 -> 8;
EOS
  test_layout <<EOS
unbalance -> 2 -> 3 -> 4 -> 5 -> e;
2 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 12 -> e;
EOS
  test_layout <<EOS
unbalance2 -> 2 -> 3 -> e;
2 -> 4 -> e;
2 -> 5 -> e;
2 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 12 -> e;
EOS
  test_layout <<EOS
unbalance3 -> 2 -> 3 -> e;
2 -> 4 -> e;
2 -> 5 -> e;
2 -> 6 -> e;
8 -> 9 -> e;
2 -> 7 -> e;
EOS
  test_layout <<EOS
disjoint -> 1 -> 2 -> 3 -> 4 -> 5 -> 6;
l1 -> l2;
l1 -> l3;
l1 -> l4;
l1 -> l5;
l1 -> l6;
EOS

  test_layout <<EOS
lol -> 2 -> 31 -> 41 -> 5;
2 -> 32 -> 42 -> 5;
31 -> 42;
41 -> 32;
EOS
  test_layout <<EOS
nestloop -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> e;
6 -> 4;
7 -> 3;
EOS
  test_layout <<EOS
escape -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8;
2 -> 21;
4 -> 6;
EOS
  test_layout <<EOS
loophead -> 1 -> loophead;
2 -> 3 -> 2;
3 -> 4;
1 -> 4;
EOS
  test_layout <<EOS
1 -> e1;
l00pz -> 1 -> l00pz;
l2 -> 2 -> l2;
2 -> e1;
2 -> e2;
l3 -> 3 -> l3;
3 -> e2;
EOS
  test_layout <<EOS
3loop -> 1 -> 3loop;
1 -> 2 -> 3  -> 2;
0 -> 00 -> 0 -> 2;
EOS
  test_layout <<EOS
foo -> 0 -> 1
0 -> 2 -> 3 -> 4 -> 5
4 -> 6
4 -> 7 -> 5
4 -> 8 -> 6
2 -> 1 -> 7
3 -> 1 -> 8
EOS
  test_layout <<EOS
dang -> 2 -> 3 -> 4 -> 5 -> 6 -> 4;
2 -> 9;
5 -> 9;
EOS
  test_layout <<EOS
dang2 -> 2 -> 3 -> 4 -> 5 -> 6 -> 4
2 -> 9
5 -> 9
9 -> a -> 9
EOS
  test_layout <<EOS
onlyloop -> onlyloop
EOS

rescue Interrupt
end

if __FILE__ == $0
  $target = ARGV[0]
  test_all
end
