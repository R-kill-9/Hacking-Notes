This vulnerability is known as Insecure Direct Object Reference (IDOR), wherein a user can directly access data owned by another user. 
- Example:
	- There exists a domain http://domain.htb/data/ where is stored different data. When we access with our user the URL that appears is http://domain.htb/data/2, that could mean that exists a sub-directory in data for each user. If we search http://domain.htb/data/0 and the information that we obtain is different we are in front of an IDOR.


For exploiting this vulnerability, we can use the **Intruder** tool avaliable on BurpSuite.
- *Set up Intruder:*
    
    - Capture the request and sent it to intruder with `Ctrl+I`.
    - Burp Suite will highlight parts of the request with payload markers (`§`). You need to place these around the parameter that you suspect might be vulnerable to IDOR.
- *Identify the parameter:*
    
    - Look for parameters in the request that might reference objects, such as `user_id`, `document_id`, `account_number`, etc.
    - Highlight the value you want to test and click "Add §" to mark it as a parameter for testing.
- *Configure the payload:*
    
    - Go to the "Payloads" tab.
    - Choose "Simple list" for payload type.
    - Input a range of values or specific IDs that you want to test. For instance, if you are testing a user ID, you might input `1, 2, 3, 4, 5` if you think these might be valid user IDs.
    - If you want to test  more than one parameter you need to select the **Cluster Bomb** option and choose a payload for each option.