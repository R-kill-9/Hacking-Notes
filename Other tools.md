# revshells.com
It's a very useful online tool that allows you to create a reverse shell in a lot of programming languages specifying the ip and the port.

# hacktricks
It's a useful page where you can find a lot of hacking information.
link: https://book.hacktricks.xyz
# Burpsuite
**Burpsuite** consists of various modules that work together to perform different security testing tasks. These modules include:

1. Proxy: It acts as an intermediary between the web browser and the target application, allowing users to intercept and modify HTTP/S requests and responses. This helps in identifying vulnerabilities and testing application behavior.
    
2. Scanner: It automatically scans web applications for common security issues, such as SQL injection, cross-site scripting (XSS), and more. It generates detailed reports highlighting the vulnerabilities found.
    
3. Intruder: It enables automated and customizable attacks on web applications, such as brute-forcing parameters, fuzzing, and performing advanced payload manipulation.
    
4. Repeater: It allows users to manually modify and resend requests to the target application, making it useful for testing specific scenarios or vulnerabilities.
    
5. Spider: It crawls through the target application, mapping out its structure and identifying potential entry points for further testing.
    
6. Sequencer: It analyzes the randomness of session tokens or other critical data to assess the strength of cryptographic algorithms or identify weaknesses in session management.

# Cookies
- It can be very useful checking the cookies of a web-site. For example if we are on a web and we have this parameters on a table:
	- role: guest
	- user: 24322
- And we know that there exists the admin role and it's userId is 34322, we can change them to gain access as admin.
	- role: admin
	- user: 34322
- After using this, if we have gained admin's account, we have a lot of opportunities to exploit the machine. For example, if as admin we can upload files we can try to do a reverse shell.

# exiftool
**exifTool** is a command-line tool and Perl library used for reading, writing, and manipulating metadata information in various file formats, particularly image and multimedia files. It allows you to extract, modify, and analyze the metadata embedded within these files.

For example, we could use it to extract metadata from a PDF file and check the "creator" field to see if it was created with a potentially vulnerable tool.

# binwalk
**binwalk** is a tool used for analyzing and extracting data from binary files, such as firmware images, executables, and other binary data. Can be very useful for extracting information from images.

# sploitus.com
**Sploitus** is a very useful web where you can find a lot of public exploits and tools.