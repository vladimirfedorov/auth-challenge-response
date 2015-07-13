# auth-challenge-response

[![NPM](https://nodei.co/npm/auth-challenge-response.png?downloads=true)](https://nodei.co/npm/auth-challenge-response/)

## Features

- Secure authentication in insecure environment
- Easy to setup 
- No database required for authentication

## Usage

Server needs to implement two routes to perform authentication process:

- challenge, e.g. `/auth/challenge`: this route will be used to send challenge and salt to the client
- authentication, e.g. `/auth/authenticate`: this route will be used to receive user password hash from the client

Optional functions for routes to check validity of created session and logout are also available. In this case minimal application that implements challenge-response authentication will be:

```javascript
    var express = require('express'),
        app = express(),
        cookieParser = require('cookie-parser'),
        auth = require('auth-challenge-response').auth(app, {checkPassword: checkPassword})
    
    // checkPassword computes password hash using 
    // the same method the client is expected to use
    function checkPassword(challenge, clientHash, cb) {
        // TODO:
        // 1. Select user password hash from the database (username)
        // 2. Compute the second hash using generated challenge (challenge)
        // 3. Compare with the received client data (data)
        // 4. If hashes do not match, send error object with the callback function
        // auth.hash is PBDKF2 using SHA-1 with 1 round
        var challengeValue = challenge.value || '',
            serverHash = auth.hash(auth.hash('password', 'user-secret'), challengeValue)
        if (challenge.username === 'username' && clientHash === serverHash) {
            cb()
        } else {
            cb({status: 403, message: 'ACCESS DENIED'})
        }   
    }

    app.use(cookieParser())
    
    // Check authentication: checks that authentication data is still valid
    // and sets res.locals.authenticated variable
    app.get('*', auth.checkAuthentication)
    
    // auth.challenge sends challenge and secret to client
    // { id: challengeId, secret: secret, value: challengeValue }
    app.get('/auth/challenge/', auth.challenge)
    
    // auth.authenticate authenticates user
    // Client sends challengeId and password hash in any format 
    // supproted by the auth-challenge-response
    // Examples:
    // Query: /auth/authenticate?id=123&hash=z80kh2n...
    // Body, to send with post request: POST /auth/authenticate with JSON body {"id":"123","hash":"z80kh2n..."}
    app.get('/auth/authenticate', auth.authenticate)
    // to support id and hash values in the req.params object:
    // app.get('/auth/authenticate/:id/:hash', auth.authenticate)

    // auth.logout destroys authentication data making 
    // client's token invalid
    // auth.logout checks cookies authToken variable, req.params.token and req.query.token in this order
    app.get('/auth/logout', auth.logout)
    
    // auth.check sends status of authentication (JSON, {valid: true/false})
    // auth.check checks cookies authToken variable, req.params.token and req.query.token in this order
    app.get('/auth/check', auth.check)

    app.get('/', function(req, res, next) {
        // Authentication result is available in res.locals.authenticated 
        var authenticated = res.locals.authenticated
        
        // ...
        
    })

    app.listen(3945, function() {
        var host = this.address().address
        var port = this.address().port
        console.log('Listening at http://%s:%s', host, port)
    })
```

## Theory

[Wiki Challenge-Response Authentication](https://en.wikipedia.org/wiki/Challenge–response_authentication)

