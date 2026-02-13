## Username Anarchy
**Username Anarchy** is a Ruby-based username generation tool used during reconnaissance and post-exploitation phases to convert **real human names into likely corporate username formats**.

It is especially useful in **Active Directory attacks**, where knowing valid usernames enables:

- User enumeration
    
- Password spraying
    
- Kerberos-based attacks
    
- Authentication testing

### Installation

Clone the repository to the attack host:

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```

The tool requires Ruby, which is installed by default on most Kali and penetration testing distributions.

### Input Format

Username Anarchy expects an input file containing **real names**, one per line.

Example `names.txt`:

```
Ben Williamson
Bob Burgerstien
Jim Stevenson
```

The tool parses first name and last name automatically.

### Basic Usage

Generate username variants from a list of names:

```bash
./username-anarchy -i names.txt
```

The output is written to standard output.

To save the results to a file:

```bash
./username-anarchy -i names.txt > usernames.txt
```


---

## Hashcat
Besides cracking passwords, **Hashcat** can also be used as a **powerful wordlist generator**. By leveraging its attack modes together with the `--stdout` option, Hashcat can generate large, highly customized wordlists without attacking any hashes. 

#### Usage

The `--stdout` flag tells Hashcat to **print generated password candidates to standard output** instead of attempting to crack hashes. This output can then be redirected to a file to create a reusable wordlist.

**Combinator Attack for Wordlist Creation (`-a 1`)**

The **combinator attack mode** combines two wordlists together, producing candidates in the form:

```
wordlist1 + wordlist2
```

Example:

```bash
hashcat --stdout -a 1 names.txt years.txt > google_combined.wordlist
```

- Combines words extracted from the names file with common years.
- Generates candidates such as:

```
mike2023
john2024
pedro1999
```


This approach is very effective for corporate or employee-based password patterns.

**Rule-Based Wordlist Expansion (`-r`)**

Hashcat can also **expand an existing wordlist using rules**, which apply transformations to each word (such as appending numbers, changing case, or replacing characters). This technique is ideal for **enhancing a previously generated wordlist**.


```bash
hashcat --stdout <created_wordlist> -r /usr/share/hashcat/rules/rockyou-30000.rule > final_wordlist
```


---

## CeWL
**CeWL** (Custom Word List generator) is a Ruby-based tool used to generate targeted wordlists by crawling websites. By extracting words from a company’s web presence, we can create a customized password list that has a higher probability of containing real employee passwords, especially when combined with rules or additional transformations.

####  Usage
- **Depth (`-d`)**: Controls how deep the spidering goes into the website.
- **Minimum word length (`-m`)**: Filters out short, less useful words.
- **Lowercase conversion (`--lowercase`)**: Ensures consistency by storing all words in lowercase.
- **Output file (`-w`)**: Specifies the file to save the generated wordlist.

```bash
cewl https://www.google.com -d 4 -m 6 --lowercase -w google.wordlist
```

- This command crawls `https://www.google.com` up to a depth of **4** pages.
    
- Words shorter than **6 characters** are ignored.
    
- All extracted words are stored in **lowercase**.
    
- The results are saved in `gooogle.wordlist`.
    
#### Verifying the Wordlist

After generating the list, you can check the total number of entries with:

```bash
wc -l google.wordlist
500
```

The output `500` indicates the wordlist contains 326 unique entries.
