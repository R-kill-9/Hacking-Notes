**Insecure Direct Object Reference (IDOR)** is an access control vulnerability that occurs when an application exposes a reference to an internal object, such as a user, document, invoice, or account, without properly verifying that the current user is authorized to access it.

The important point is that the identifier itself is not the vulnerability. The vulnerability exists when the server trusts a user-controlled identifier and fails to perform the corresponding authorization check.

A typical example is:

```http
GET /data/2 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

If changing `2` to another identifier allows the same user to access another user's data:

```http
GET /data/3 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

the application may be vulnerable to IDOR.

---

## Identifying object references

IDORs commonly appear wherever the client can directly specify which object it wants to access.

Typical parameters include:

```text
user_id
account_id
document_id
invoice_id
order_id
file_id
```

They can appear in different locations:

```http
GET /api/users/123/profile HTTP/2
```

```http
GET /download?file_id=123 HTTP/2
```

```http
POST /api/orders HTTP/2

{"order_id":123}
```

The first step is to identify values that reference an object and determine whether changing them affects which resource is returned.

For example:

```http
GET /data/2 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

Change the identifier:

```http
GET /data/0 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

If the response contains information belonging to another user, this indicates an authorization failure.

---

## Exploitation with Burp Suite

Burp Repeater is usually sufficient when testing individual object references.

Send the original request to Repeater and modify the suspected identifier manually:

```http
GET /data/2 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

Then test:

```http
GET /data/1 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

```http
GET /data/3 HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

Compare the responses. A successful IDOR is not simply a different HTTP response; you need to confirm that the returned object belongs to a user or context that the current account should not be able to access.

---

## Enumerating object identifiers

When identifiers are predictable or sequential, Burp Intruder can automate testing.

Send the request to Intruder and mark the object identifier as the payload position:

```http
GET /data/§2§ HTTP/2
Host: domain.htb
Cookie: session=USER_SESSION
```

Use a **Simple list** or numeric payload to test multiple identifiers:

```text
0
1
2
3
4
5
6
7
8
9
```

Then compare the responses by status code, response length, or content.

For example:

```text
Request      Status    Length
/data/1      200       1842
/data/2      200       1837
/data/3      403        421
/data/4      200       1912
```

The interesting responses must then be inspected manually to determine whether they expose another user's object.

For multiple independent identifiers, Burp Intruder's **Cluster bomb** attack type can be used when the application requires combinations of different parameters.

---

## Horizontal and vertical access

IDOR is commonly associated with **horizontal privilege escalation**, where one user accesses another user's objects at the same privilege level.

```text
User A
  |
  | /documents/456
  v
User B's document
```

A related authorization failure can occur when a lower-privileged user accesses an administrator's object or functionality. This is generally described as **vertical privilege escalation**.

```text
Normal user
    |
    | /admin/users/1
    v
Administrator resource
```

The distinction is useful during testing because changing an object identifier may reveal either another user's data or a higher-privileged resource.

---

## Important distinction

An unpredictable identifier such as a UUID does **not** fix IDOR by itself.

For example:

```text
GET /documents/550e8400-e29b-41d4-a716-446655440000
```

is harder to enumerate than:

```text
GET /documents/123
```

but the application must still perform an authorization check.

The fundamental question during testing is therefore not:

> Can I guess another ID?

but:

> If I provide another valid object ID, does the server verify that I am authorized to access that object?