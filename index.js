var settings = require('./config/config.json');

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise  = require('promise');

const serverless = require('serverless-http');
const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

var auth = new LdapAuth(settings.ldap);

app.set('jwtTokenSecret', settings.jwt.secret);

var authenticate = function (username, password) {
	return new Promise(function (resolve, reject) {
		auth.authenticate(username, password, function (err, user) {
			if(err)
				reject(err);
			else if (!user)
				reject();
			else
				resolve(user);
		});
	});
};

app.post('/auth', function (req, res) {
	var data = JSON.parse(req.body.toString());

	if(data.username && data.password) {
		authenticate(data.username, data.password)
			.then(function(user) {
				var expires = parseInt(moment().add(2, 'minutes').format("X"));
				var token = jwt.encode({
					exp: expires,
					user_name: user.uid,
					full_name: user.cn,
					mail: user.mail
				}, app.get('jwtTokenSecret'));

				res.json({token: token, full_name: user.cn});
			})
			.catch(function (err) {
				console.log(err);

				if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i)) ) {
					res.status(401).send({ error: 'Wrong user or password'});
				} else {
					res.status(500).send({ error: 'Unexpected Error'});
					auth = new LdapAuth(settings.ldap);
				}

			});
	} else {
		res.status(400).send({error: 'No username or password supplied'});
	}
});

app.post('/verify', function (req, res) {
	var token = JSON.parse(req.body.toString()).token;
	if (token) {
		try {
			var decoded = jwt.decode(token, app.get('jwtTokenSecret'));

			if (decoded.exp <= parseInt(moment().format("X"))) {
				res.status(400).send({ error: 'Access token has expired'});
			} else {
				res.json(decoded);
			}
		} catch (err) {
			res.status(500).send({ error: 'Access token could not be decoded'});
		}
	} else {
		res.status(400).send({ error: 'Access token is missing'});
	}
});

module.exports.handler = serverless(app);
