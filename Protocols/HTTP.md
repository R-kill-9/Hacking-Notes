**HTTP** is a text-based communication protocol used for data exchange between clients (browsers, API clients) and web servers. It operates over TCP/IP and follows a request-response model.

## Versions
- **HTTP/1.0**: Requires a new connection for each request.  
- **HTTP/1.1**: Added persistent connections, chunked transfer encoding, and better caching mechanisms.  
- **HTTP/2**: Improved performance with multiplexing, header compression, and server push.  
- **HTTP/3**: Uses QUIC instead of TCP, reducing latency and improving security.  

## HTTP Methods
- **GET**: Retrieves a resource without modifying it.  
- **POST**: Submits data to the server, often creating a resource.  
- **PUT**: Updates or creates a resource at a specified URL.  
- **DELETE**: Removes a specified resource.  
- **PATCH**: Partially updates a resource.  
- **HEAD**: Similar to GET but returns only headers.  
- **OPTIONS**: Describes the communication options for a resource.  
- **TRACE**: Echoes back the received request. 


## Status Codes
- **1xx (Informational)**: Processing information (e.g., `100 Continue`).  
- **2xx (Success)**: Request was successful (e.g., `200 OK`, `201 Created`).  
- **3xx (Redirection)**: Further action is needed (e.g., `301 Moved Permanently`, `302 Found`).  
- **4xx (Client Errors)**: The client made an invalid request (e.g., `400 Bad Request`, `403 Forbidden`, `404 Not Found`).  
- **5xx (Server Errors)**: The server encountered an error (e.g., `500 Internal Server Error`, `503 Service Unavailable`).  

## Headers
HTTP headers provide metadata about the request or response. Examples:  
- **Content-Type**: Specifies the media type of the response.  
- **User-Agent**: Identifies the client making the request.  
- **Authorization**: Includes authentication credentials.  
- **Cache-Control**: Controls caching behavior.  
- **Set-Cookie**: Sends cookies from the server to the client.  
