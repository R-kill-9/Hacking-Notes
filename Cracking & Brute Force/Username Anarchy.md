**Username Anarchy** is a Ruby-based username generation tool used during reconnaissance and post-exploitation phases to convert **real human names into likely corporate username formats**.

It is especially useful in **Active Directory attacks**, where knowing valid usernames enables:

- User enumeration
    
- Password spraying
    
- Kerberos-based attacks
    
- Authentication testing
    

Username Anarchy focuses on generating **realistic, organization-style usernames**, not brute-force strings.

---
## Installation

Clone the repository to the attack host:

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```

The tool requires Ruby, which is installed by default on most Kali and penetration testing distributions.

---
## Input Format

Username Anarchy expects an input file containing **real names**, one per line.

Example `names.txt`:

```
Ben Williamson
Bob Burgerstien
Jim Stevenson
```

The tool parses first name and last name automatically.

---

## Basic Usage

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

## Username Patterns Generated

Username Anarchy generates multiple realistic formats, including:

- First initial + last name  
    `bwilliamson`
    
- First name + last name  
    `benwilliamson`
    
- First name . last name  
    `ben.williamson`
    
- Last name . first name  
    `williamson.ben`
    
- Shortened names  
    `benw`, `bwilli`
    
- Legacy-compatible formats  
    `willib`, `bwill`
    
- Separator variations (`.`, `_`, `-`)
    

The exact output depends on the internal rules and name length.

---

## Customization and Options

Username Anarchy supports additional flags to refine output:

- Control capitalization
    
- Include or exclude separators
    
- Generate shorter usernames for legacy systems
    
- Adjust output verbosity
    

Example:

```bash
./username-anarchy -i names.txt --case lower
```
