An API is a set of rules and protocols for building and interacting with software applications. It defines the methods and data formats that applications can use to communicate with each other, typically over the internet. APIs enable different software systems to connect, share data, and perform actions without needing to understand each other's internal workings.
## API Recon

#### Identify the API Endpoints

- **Documentation**: Check if there's official documentation.
- **Web Application**: Inspect the web application for API calls using browser developer tools.
- **Common Endpoints**: Test common paths like `/api/`, `/v1/`, `/users/`, etc.
#### Analyze HTTP Methods

Understanding HTTP actions is crucial for API hacking as it allows you to interact with web services, test for vulnerabilities, and exploit weaknesses by manipulating requests and responses.

- **GET**: Retrieve data.
- **POST**: Create data.
- **PUT**: Update data.
- **DELETE**: Delete data.
- **PATCH**: Partially update data.
- **OPTIONS**: Check supported methods.
#### Inspect Request and Response Structures

- **Headers**: Check for authentication tokens, content types, etc.
- **Parameters**: Identify required and optional parameters.
- **Data Formats**: Note the data formats (JSON, XML).
- **Response Codes**: Understand different response codes and their meanings.
## Mass assignment vulnerabilities
Mass assignment, also known as auto-binding, is a feature in many web development frameworks that automatically takes input data from a user's request and assigns it to corresponding fields in an internal object. This feature is designed to simplify and speed up the development process by reducing the amount of boilerplate code needed to handle user input.
#### Example Scenario

Users can update their username and email using the following JSON:

**PATCH Request**

```bash
{
    "username": "kill-9",
    "email": "kill-9@example.com"
}
```

When retrieving user details, the following JSON is returned:

**GET Response**
```bash
{
    "id": 999,
    "name": "kill-9",
    "email": "kill-9@example.com",
    "isAdmin": "false"
}
```
**Exploiting Mass Assignment**

If the application uses mass assignment to update user data, an attacker could send additional parameters in the update request, potentially altering fields that should not be modifiable by the user.

#### Malicious PATCH Request

An attacker might send the following request to elevate their privileges:

**POST Resquest**
```bash
{
    "username": "kill-9",
    "email": "kill-9@example.com",
    "isAdmin": "true"
}
```
If the application does not properly restrict which fields can be updated, the attacker’s request would result in the user being updated with admin privileges.

## Server Side Parameter Pollution (SSPP)
Some systems have internal APIs that cannot be accessed directly from the internet. Server-side parameter pollution happens when a website takes user input and includes it in a request to an internal API without properly encoding it. This lack of encoding can allow an attacker to alter or inject parameters, potentially enabling them to:

- Replace existing parameters with new ones.
- Change how the application behaves.
- Gain access to data they shouldn't be able to see.

#### Truncating query strings
You can use a URL-encoded `#` character to try to cut off the server-side request. To make the response easier to understand, you can add some text after the # character.

For example, you could change the query string like this:
```
GET /userSearch?name=kill-9%23foo&back=/home
```

The front-end will then attempt to access this URL:
```
GET /users/search?name=kill-9#foo&publicProfile=true
```
#### Injecting invalid parameters
You can use a URL-encoded & character to try to add an additional parameter to the server-side request.

For instance, you could change the query string like this:
```
GET /userSearch?name=kill-9%26foo=xyz&back=/home
```
#### Overriding existing parameters
To determine if an application is vulnerable to server-side parameter pollution, one effective test involves attempting to override an existing parameter. This method entails injecting a secondary parameter with identical naming.

For instance, you could adjust the query string in this manner:
```
GET /userSearch?name=peter%26name=carlos&back=/home
```

When the internal API encounters two occurrences of the name parameter, its response depends on how it interprets and manages multiple parameters with the same identifier. The behavior can vary depending on the application's technology stack.

Successful override of the original parameter can potentially lead to exploitation. For instance, injecting name=administrator might grant unauthorized access under the guise of an administrator user.

