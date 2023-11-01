# `user-data`

## Overview

In any application that deals with user data, it is crucial for developers to handle this data with care and ensure its security. User data often contains sensitive information, and it is essential to understand and safeguard this information to prevent legal implications and protect user privacy.

The repository will answer this questions:

- What is **personal data** and **Personally Identifiable Information (PII)**?
- How do you implement **basic auth system**
- How do you perform **session authentication**(cookies)
- How do you perform **user authentication**

This repository covers the following topics:

1. `Personal Data`

   - Implements a log filter that obfuscates PII fields to prevent unintentional exposure.
   - Encrypts passwords and securely validating user input passwords.
   - Authenticates to a database using environment variables to protect sensitive connection information.

2. `Basic Authentication`

   - Performs a Base64 encoding
   - Encodes a string in Base64
   - Sends authorization header using a POST method to allow authorization


3. `Session Authentication`

   - Implements session authentication
   - Illustrates what cookies are by sending and parsing them

4. `User Authentication`
  
   - Declares routes is a Flask Application
   - Gets and Sets Cookies
   - Retrieves request form data
   - Returns various HTTP status codes


## Disclaimer
The guidelines and applications in this project are for practice purposes
