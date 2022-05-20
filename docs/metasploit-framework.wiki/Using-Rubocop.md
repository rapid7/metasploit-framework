# Rubocop
Rubocop is a great tool for beginning and experienced Ruby coders.  Previously, we suggested that developers run Rubocop on code to give suggestions for improvement.  Since then, we've worked hard to get the rules right, and now we ask everyone submitting ruby code to run the code through rubocop with automatic fixes enabled.

## Installing Rubocop
[Installing Rubocop](https://github.com/bbatsov/rubocop) is really easy.  Simply go to your metasploit-framework directory and run:
```gem install rubocop```

## Running Rubocop
Run ```rubocop -a <ruby file>```

#### But I copied it from another module!
Consistency is a virtue only when it is correct.  (In all seriousness, use your best judgement here, and don't be afraid to ask.). Also, we allow cleaning up other modules too, though be forewarned, please have a way to test any modules you clean up!
