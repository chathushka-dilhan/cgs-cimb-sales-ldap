var settings = require('./config/config.json');
var jwt = require('jwt-simple');
var moment = require('moment');
const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('jwtTokenSecret', settings.jwt.secret);
app.disable("x-powered-by");

exports.handler =  function(event, context, callback) {
    var token = event.authorizationToken;
    if (token) {
		try {
			var decoded = jwt.decode(token, app.get('jwtTokenSecret'));

			if (decoded.exp <= parseInt(moment().format("X"))) {
				callback(null, generatePolicy('user', 'Deny', event.methodArn, { error: 'Access token has expired'}))
			} else {
				callback(null, generatePolicy('user', 'Allow', event.methodArn, decoded))
			}
		} catch (err) {
			callback(null, generatePolicy('user', 'Deny', event.methodArn, { error: 'Access token could not be decoded'}))
		}
	} else {
		callback(null, generatePolicy('user', 'Deny', event.methodArn, event))
	}
};

var generatePolicy = function(principalId, effect, resource, msg) {
    var authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    authResponse.context = msg;
    return authResponse;
}