It is possible run Nmap scans directly within the Metasploit console.

```bash
db_nmap -sV -p 80,443 <target>
```

For reviewing the results you can use:

```bash
services -p <port> -u
```

## Import Nmap Results 

To include an Nmap scan file in Metasploit, you can import it to analyze and use the discovered hosts and services in your exploitation workflow. 
1. **Perform an Nmap Scan with XML Output**  
Run your Nmap scan and save the results in an XML file using the `-oX` option:

```bash
nmap -sV -oX scan_results.xml 192.168.1.0/24
```

2. **Open Metasploit Framework (msfconsole)**

```bash
msfconsole
```

3. **Import the Nmap XML File**  
Use the `db_import` command to import the scan results:

```bash
db_import /path/to/scan_results.xml
```

4. **Verify Imported Data**  
Check the imported hosts and services with these commands:

- List hosts: `hosts`
- List services: `services`

It is possible to find the "Database not connected" error if the PostgreSQL database is not running or configured. To fix it, execute the following commands:

```bash
# Start PostgreSQL
sudo service postgresql start
# If it's the first time initialize the DB
sudo msfdb init
# In msfconsole, check connection
db_status
# Turn off the DB when you are finished
sudo service postgresql stop
```

Once the data is imported, we can continue using the nmap command, and all the results we find will be saved in the msf database.