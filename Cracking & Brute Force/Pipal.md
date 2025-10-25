[Pipal](https://copilot.microsoft.com/chats/k4rC7xm1jSsKwE2ocQHUR) is a Ruby-based password analysis tool developed by Robin Wood (aka digininja). It's designed to process large dumps of cracked passwords and generate detailed statistics to help security professionals understand password patterns and weaknesses.

## Installation & Requirements

- Requires **Ruby 1.9.x or newer**
- No external gems needed — works on vanilla Ruby installs

```bash
# Clone the repository
git clone https://github.com/digininja/pipal.git
cd pipal

# Run help command
ruby pipal.rb -?
```


---

## Usage Syntax
```bash
ruby pipal.rb [OPTIONS] FILENAME
```

**Common Options:**
```bash
--help, -h         # Show help
--top, -t X        # Show top X results (default: 10)
--output, -o FILE  # Output results to a file
--external, -e FILE# Compare against external wordlist
--gkey <API_KEY>   # Google Maps API key for ZIP code lookups
```

This command will produce a report including:

- Most common passwords
    
- Most frequent password lengths
    
- Use of special characters, digits, uppercase letters
    
- Pattern distributions (e.g., dates, names, keyboard sequences)

