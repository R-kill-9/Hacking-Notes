**Website Defacing via Cross-Site Scripting (XSS)** refers to modifying the visual appearance or content of a website by injecting malicious JavaScript code through an XSS vulnerability.

Defacing typically aims to display a message indicating that the attacker successfully compromised the website. While several vulnerabilities can lead to website defacement, **Stored XSS vulnerabilities are commonly used** because the injected payload is saved on the server and automatically executed for every visitor.

Unlike temporary modifications performed in a browser console, defacing through XSS affects all users who access the vulnerable page, making it visible to administrators, customers, and the public.

---

## Purpose of Website Defacing

Defacing attacks are often carried out to publicly demonstrate that a website has been compromised. Attackers frequently replace the page content with a short message, a logo, or other visual changes.

These attacks may have several motivations:

- Demonstrating successful exploitation of a vulnerability
    
- Gaining public attention or recognition
    
- Damaging the reputation of an organization
    
- Delivering political or ideological messages
    

Since the attack modifies the page that users normally interact with, it can have **significant reputational and financial consequences** for organizations.

---

## Changing the Background

A common visual modification is altering the background color of the page. Many defacement attacks use dark colors to make the message more visible.

Example payload:

```html
<script>document.body.style.background = "#141d2b"</script>
```

This JavaScript code modifies the CSS background property of the page body, changing the page color for anyone visiting the vulnerable page.

Another option is to replace the background with an image.

Example payload:

```html
<script>document.body.background = "https://example.com/image.png"</script>
```

Using an image background allows attackers to display logos, graphics, or other visual messages.

---

## Changing the Page Title

The title displayed in the browser tab can also be modified through JavaScript. Changing the title helps reinforce the visual effect of the defacement.

Example payload:

```html
<script>document.title = "Website Compromised"</script>
```

Once executed, the browser tab will display the new title instead of the original one.

---

## Modifying Page Content

To alter the content displayed to users, attackers can manipulate DOM elements using JavaScript.

For example, the content of a specific element can be replaced using the `innerHTML` property.

```javascript
document.getElementById("content").innerHTML = "New Text"
```

This approach targets a single element within the page.

However, many defacing attacks replace the entire page content. This can be achieved by modifying the body element directly.

Example payload:

```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

This replaces the entire page body with new content controlled by the attacker.

---

## Injecting Custom HTML Content

Instead of displaying plain text, attackers often inject custom HTML to present a message in a structured format.

Example HTML message:

```html
<center>
<h1 style="color:white">Website Compromised</h1>
<p style="color:white">Security Breach Detected</p>
</center>
```

To inject this content through XSS, the HTML must be placed inside a JavaScript string and inserted into the page using `innerHTML`.

Example payload:

```html
<script>
document.getElementsByTagName('body')[0].innerHTML =
'<center><h1 style="color:white">Website Compromised</h1><p style="color:white">Security Breach Detected</p></center>'
</script>
```

When executed, the original content of the page is replaced with the injected message.

---

## Combining Multiple Defacing Actions

More advanced defacing payloads combine several modifications in a single attack.

For example:

```html
<script>
document.body.style.background="#141d2b";
document.title="Website Compromised";
document.getElementsByTagName('body')[0].innerHTML='<center><h1 style="color:white">Website Compromised</h1></center>';
</script>
```

This payload:

- Changes the page background
    
- Replaces the browser tab title
    
- Replaces the entire page content
    

Together, these modifications create a complete defaced page.


