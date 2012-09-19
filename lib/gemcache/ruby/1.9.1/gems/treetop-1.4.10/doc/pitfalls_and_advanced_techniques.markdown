#Pitfalls
##Left Recursion
An weakness shared by all recursive descent parsers is the inability to parse left-recursive rules. Consider the following rule:

    rule left_recursive
      left_recursive 'a' / 'a'
    end
    
Logically it should match a list of 'a' characters. But it never consumes anything, because attempting to recognize `left_recursive` begins by attempting to recognize `left_recursive`, and so goes an infinite recursion. There's always a way to eliminate these types of structures from your grammar. There's a mechanistic transformation called _left factorization_ that can eliminate it, but it isn't always pretty, especially in combination with automatically constructed syntax trees. So far, I have found more thoughtful ways around the problem. For instance, in the interpreter example I interpret inherently left-recursive function application right recursively in syntax, then correct the directionality in my semantic interpretation. You may have to be clever.

#Advanced Techniques
Here are a few interesting problems I've encountered. I figure sharing them may give you insight into how these types of issues are addressed with the tools of parsing expressions.

##Matching a String

    rule string
      '"' (!'"' . / '\"')* '"'
    end

This expression says: Match a quote, then zero or more of any character but a quote or an escaped quote followed by a quote. Lookahead assertions are essential for these types of problems.

##Matching Nested Structures With Non-Unique Delimeters
Say I want to parse a diabolical wiki syntax in which the following interpretations apply.

    ** *hello* ** --> <strong><em>hello</em></strong>
    * **hello** * --> <em><strong>hello</strong></em>

    rule strong
      '**' (em / !'*' . / '\*')+ '**'
    end
    
    rule em
      '**' (strong / !'*' . / '\*')+ '**'    
    end
    
Emphasized text is allowed within strong text by virtue of `em` being the first alternative. Since `em` will only successfully parse if a matching `*` is found, it is permitted, but other than that, no `*` characters are allowed unless they are escaped.

##Matching a Keyword But Not Words Prefixed Therewith
Say I want to consider a given string a characters only when it occurs in isolation. Lets use the `end` keyword as an example. We don't want the prefix of `'enders_game'` to be considered a keyword. A naiive implementation might be the following.

    rule end_keyword
      'end' &space
    end
    
This says that `'end'` must be followed by a space, but this space is not consumed as part of the matching of `keyword`. This works in most cases, but is actually incorrect. What if `end` occurs at the end of the buffer? In that case, it occurs in isolation but will not match the above expression. What we really mean is that `'end'` cannot be followed by a _non-space_ character.

    rule end_keyword
      'end' !(!' ' .)
    end
    
In general, when the syntax gets tough, it helps to focus on what you really mean. A keyword is a character not followed by another character that isn't a space.