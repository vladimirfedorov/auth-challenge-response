var pbkdf2 = require('pbkdf2'),
    challengeStore = 'auth_pbkdf2_challengeStore',
    authStore = 'auth_pbkdf2_authStore',
    defaultAuthExpiration = 60 * 60,
    defaultChallengeExpiration = 30

// params: 
//   secret - salt, challenge.k1 that is sent to the client
//   authExpiration - (seconds) expiration time for auth, default is 1 hour
//   challengeExpiration - (seconds) expireation time for auth, default is 30 seconds
//   checkPassword - function(username, challenge, authenticationData, cb(error, success))
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
    
    function dateToInt(date) {
        return parseInt(date.toISOString().replace(/\D/g, '').substr(0,14))
    }

    function randomString(length) {
        return Math.round((Math.pow(36, length + 1) - Math.random() * Math.pow(36, length))).toString(36).slice(1);

    }

    function randomId() {
        return parseInt(Math.random().toString(10).substr(2))
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
        var token = (req.cookies || {}).authToken || req.params.token,
            isValid = checkAuthentication(token)
        
        res.locals.authenticated = isValid
        next()
    }
    
    
    this.check = function(req, res, next) {
        var token = (req.cookies || {}).authToken || req.params.token,
            isValid = checkAuthentication(token)
        res.status(200).send({valid: isValid})
        next()
    }
    
    this.challenge = function(req, res, next) {
        var challengeId = randomId(),
            challengeValue = randomString(100),
            challengeExpiration = params.challengeExpiration || defaultChallengeExpiration,
            secret = params.secret || '',
            dateExpires = new Date(),
            challenge = {
                id: challengeId,
                k1: secret,
                k2: challengeValue
            }
        
        checkStores()

        dateExpires.setSeconds(dateExpires.getSeconds() + challengeExpiration)
        challenge.expires = dateToInt(dateExpires)
        app.locals[challengeStore][challengeId] = challenge
        res.status(200).send({id: challengeId, k1: secret, k2: challengeValue})
        next()
    }
    
    this.authenticate = function (req, res, next) {
        
        var body = req.body || {},
            username = body.username || req.params.username,
            challengeId = body.id || req.params.id,
            challenge = app.locals[challengeStore][challengeId],
            k3 = body.k3 || req.params.k3
        
        checkStores()

        if (challenge) {    
            challenge.k3 = k3

            app.locals[challengeStore][challengeId] = undefined
            params.checkPassword(username, challenge, req.body, function(error) {
                var authToken = randomString(100),
                    dateExpires = new Date(),
                    authExpiration = params.authExpiration || defaultAuthExpiration

                if (error) {
                    res.status(error.status).send(error)
                } else {
                    dateExpires.setSeconds(dateExpires.getSeconds() + authExpiration)
                    app.locals[authStore][authToken] = { username: username, token: authToken, expires: dateToInt(dateExpires) } 
                    res.cookie('authToken', authToken)
                    res.status(200).send({authToken: authToken})
                }
            })
        } else {
            res.status(200).send()
        }
        next()
    }
    
    this.logout = function(req, res, next) {
        var token = (req.cookies || {}).authToken || req.params.token
        checkStores()
        if (token && app.locals[authStore][token]) app.locals[authStore][token] = undefined
        res.clearCookie('authToken')
        res.status(200).send()
        next()
    }
    
    return this
}

