# Rubocop
Rubocop is a great tool for beginning and experienced Ruby coders if you treat the output for what it is: suggestions.  While msftidy remains our barrier to entry, there are many things it will not catch.  As msftidy is not strict enough to catch everything, Rubocop sometimes goes too far in its suggestions.

## Installing Rubocop
[Installing Rubocop](https://github.com/bbatsov/rubocop) is really easy.  Simply go to your metasploit-framework directory and run:
```gem install rubocop```

## Running Rubocop
Run ```rubocop <ruby file>```

## What is Cyclomatic Complexity?
Don't worry about it.  Metasploit Project uses msftidy as the minimum barrier to submitting code, but we strongly encourage contributors to run their ruby code through Rubocop.  Where Msftidy does the bare minimum, Rubocop sometimes goes too far.  Treat the output of Rubocop as a suggestion, not really as a black and white rule.  Part of that reason is because at best, the Metasploit team probably only agrees on 50% of the suggestions from Rubocop.  Other suggestions can bleed into snide comments, coding holy wars, and Nerf battles that last until we forget why we were fighting.

## So what suggestions should you take to heart?

#### Spacing
White space affects code readability, and we'd like to try and maintain (or establish) a continual look and feel.  If Rubocop complains about whitespace, please take it to heart.

#### Parentheticals, braces, and brackets
Rubocop likes aligned parentheses, spaces around brackets, and is picky about spacing around most encapsulating syntax elements.  As a big fan of Python, I agree wholeheartedly with these alignment and spacing suggestions, as it makes me feel like I'm home.  Others will disagree about importance, but no one will complain if you do it right, only varying volumes of complaining when doing it wrong.

#### Code Complexity
As stated above, Rubocops's code complexity warnings are less useful than we'd like.  Please keep functions below 100 lines (50 is better).  Otherwise, just be clear.  If two lines will be readable, use two lines.  Someone will be coming along behind you.  Please do not make that person hate you. We do have most of the rubocop warnings disabled, but use your head.

#### Conditional Statements
Rubocop encourages single-line incomprehensible conditional statements that reek of blatant, painful, Ruby exhibitionism.  Again, as a non-native Ruby coder that has to go back and figure out what old modules do, I humbly request that you please ignore those warnings.  Make your conditional statements easy to read and understand, make them stand out as conditional, and please, never, ever use `unless`.  I've watched `unless` screw up very good, talented, experienced coders.  I've also watched senior members of our team snap and `git grep` through the codebase ripping out `unless` statements and muttering unpleasant things the entire time.
If your conditional statement takes up two whole lines, so be it.  If two nested conditional statements can be replaced with a single, unreadable and impossible to debug multi-line complex statement, please leave the two statements in place.

#### Ternary Operations
This is likely never to come up, but if it does, please don't use ternary operators. If you do use them, think about the case where there might be a backtrace - will you know which path was taken? Note that if you're just trying to assign based on conditional, ruby also supports this syntax which can be clearer if your branches are complex:

```
a = if x = y
      foo
    else
      bar
    end
```

#### But I copied it from another module!
Consistency is a virtue only when it is correct.  (In all seriousness, use your best judgement here, and don't be afraid to ask.). Also, we allow cleaning up other modules too, though be forewarned, have a way to actually test modules you cleanup.
