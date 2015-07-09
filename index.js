var pbkdf2 = require('pbkdf2'),
    challengeStore = 'auth_pbkdf2_challengeStore',
    authStore = 'auth_pbkdf2_authStore',
    defaultAuthExpiration = 60 * 60,
    defaultChallengeExpiration = 30

// params: 
//   secret - salt, challenge.salt that is sent to the client, or function(username, cb(secret))
//   authExpiration - (seconds) expiration time for auth, default is 1 hour
//   challengeExpiration - (seconds) expireation time for auth, default is 30 seconds
//   checkPassword - function(challenge, clientHash, cb(error, success))
module.exports.auth = function(app, params) {

    function checkStores() {
        var dateNow = dateToInt(new Date())
        
        // init stores on start
        if (app.locals[challengeStore] === undefined) app.locals[challengeStore] = {}
        if (app.locals[authStore] === undefined) app.locals[authStore] = {}
        
        // remove outdated challenges
        for (var k in app.locals[challengeStore]) {
            challenge = app.locals[challengeStore][k]
            if (challenge && challenge.expires < dateNow) {
                app.locals[challengeStore][k] = undefined
            }
        }
        
        // remove outdated tokens
        for (var k in app.locals[authStore]) {
            auth = app.locals[authStore][k]
            if (auth && auth.expires < dateNow) {
                app.locals[authStore][k] = undefined
            }
        }
    }
    
    function hash(value, salt) {
        return pbkdf2.pbkdf2Sync(value, salt, 1, 32, 'sha1').toString('hex')
    }
    
    function randomString(length) {
        return Math.round((Math.pow(36, length + 1) - Math.random() * Math.pow(36, length))).toString(36).slice(1);

    }

    function randomId() {
        return parseInt(Math.random().toString(10).substr(2))
    }

    function dateToInt(date) {
        return parseInt(date.toISOString().replace(/\D/g, '').substr(0,14))
    }

    function checkAuthentication(token) {
        var isValid = false,
            authObj = {}, 
            dateNow = dateToInt(new Date())
        
        if (token && token.length > 0) {
            checkStores()
            authObj = app.locals[authStore][token]
            if (authObj) {
                if (authObj.expires > dateNow) {
                    isValid = true
                } else {
                    app.locals[authStore][authToken] = undefined   
                }
            }
        }

        return isValid
    }
    
    this.hash = function(value, salt) {
        return hash(value, salt)
    }
    
    this.checkAuthentication = function (req, res, next) {
        var token = (req.cookies || req.body || {}).authToken || req.params.token || req.query.token,
            isValid = checkAuthentication(token)
        res.locals.authenticated = isValid
        next()
    }
    
    
    this.check = function(req, res, next) {
        var token = (req.cookies || req.body || {}).authToken || req.params.token || req.query.token,
            isValid = checkAuthentication(token)
        if (!isValid) res.clearCookie('authToken')
        res.status(200).send({valid: isValid})
        next()
    }
    
    this.challenge = function(req, res, next) {
        
        function storeAndSend(challenge) {
            var c = { id: challenge.id, secret: challenge.secret, value: challenge.value }
            app.locals[challengeStore][challengeId] = challenge
            res.status(200).send(c)
            next()
        }
        
        var username = (req.body || {}).username || req.params.username || req.query.username || '',
            challengeId = randomId(),
            challengeValue = randomString(50),
            challengeExpiration = params.challengeExpiration || defaultChallengeExpiration,
            secret = params.secret || '',
            dateExpires = new Date(),
            challenge = {
                id: challengeId,
                secret: secret,
                value: challengeValue,
                username: username
            }
        
        checkStores()
        dateExpires.setSeconds(dateExpires.getSeconds() + challengeExpiration)
        challenge.expires = dateToInt(dateExpires)
        
        if (typeof secret === 'function') {
            secret(username, function(secretValue) {
                challenge.secret = secretValue
                storeAndSend(challenge)
                next()
            })
        } else {
            storeAndSend(challenge)
            next()
        }
    }
    
    this.authenticate = function (req, res, next) {        
        var body = req.body || {},
            challenge = undefined,
            challengeId = body.id || req.params.id || req.query.id,
            clientHash = body.hash || req.params.hash || req.query.hash
        
        checkStores()

        challenge = app.locals[challengeStore][challengeId]
        
        if (challenge) {    
            app.locals[challengeStore][challengeId] = undefined
            params.checkPassword(challenge, clientHash, function(error) {
                var authToken = randomString(50),
                    dateExpires = new Date(),
                    authExpiration = params.authExpiration || defaultAuthExpiration

                if (error) {
                    res.status(error.status).send(error)
                } else {
                    dateExpires.setSeconds(dateExpires.getSeconds() + authExpiration)
                    app.locals[authStore][authToken] = { username: challenge.username, token: authToken, expires: dateToInt(dateExpires) } 
                    res.cookie('authToken', authToken)
                    res.status(200).send({authToken: authToken})
                }
                next()
            })
        } else {
            params.checkPassword({}, hash, function(error) {
                res.status(error.status).send(error)
                next()
            })
        }
    }
    
    this.logout = function(req, res, next) {
        var token = (req.cookies || {}).authToken || req.params.token || req.query.token
        checkStores()
        if (token && app.locals[authStore][token]) app.locals[authStore][token] = undefined
        res.clearCookie('authToken')
        res.status(200).send()
        next()
    }
    
    return this
}