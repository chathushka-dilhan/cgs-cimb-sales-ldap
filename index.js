var settings = require('./config/config.json');

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise = require('promise');

//app = require('express')();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(require('cors')());

var auth = new LdapAuth(settings.ldap);

app.set('jwtTokenSecret', settings.jwt.secret);

var authenticate = function (username, password) {
    console.log("Username: " + username + ", Password: " + password);
    console.log("Settings: " + settings);
    return new Promise(function (resolve, reject) {
        auth.authenticate(username, password, function (err, user) {
            if (err)
                reject(err);
            else if (!user)
                reject();
            else
                resolve(user);
        });
    });
};

var response = {};

exports.handler = async function (event, context, callback) {
    //var data = JSON.stringify(event, null, 2);
    console.log("EVENT: \n" + event);
//app.post('/authenticate', function (req, res) {
    //console.log(req);
    if (event.username && event.password) {
        authenticate(event.username, event.password)
            .then(function (user) {
                var expires = parseInt(moment().add(1, 'days').format("X"));
                const token = jwt.encode({
                    exp: expires,
                    user_name: user.uid,
                    full_name: user.cn,
                    mail: user.mail
                }, app.get('jwtTokenSecret'));

                console.log("Token: " + token);
                response = { token: token, full_name: user.cn };
                //res.json({ token: token, full_name: user.cn });
                console.log("Response: " + JSON.stringify(response));
                //return token;
            })
            .then(callback(null, {
                statusCode: 200,
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(response),
            }))
            .catch(function (err) {
                console.log(err);

                if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i))) {
                    callback(null, {
                        statusCode: 401,
                        headers: {
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({ error: 'Wrong user or password' }),
                    });
                    //res.status(401).send({ error: 'Wrong user or password' });
                } else {
                    //res.status(500).send({ error: 'Unexpected Error' });
                    auth = new LdapAuth(settings.ldap);
                    callback(null, {
                        statusCode: 500,
                        headers: {
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({ error: 'Unexpected Error' }),
                    });
                }

            });
    } else {
        console.error("No username or password supplied");
        //res.status(400).send({ error: 'No username or password supplied' });
        callback(null, {
            statusCode: 400,
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ error: 'No username or password supplied' }),
        });
    }
}

/*var port = (process.env.PORT || 3000);
app.listen(port, function () {
    console.log('Listening on port: ' + port);

    if (typeof settings.ldap.reconnect === 'undefined' || settings.ldap.reconnect === null || settings.ldap.reconnect === false) {
        console.warn('WARN: This service may become unresponsive when ldap reconnect is not configured.')
    }
});*/