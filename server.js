// server.js
// where your node app starts

// init project
const express = require('express');
const session = require('express-session');
const request = require('request');
const https = require('https');
const fs = require('fs');
const identityServices = require('./isamservices.js')
const app = express();

// set to ignore ssl cert errors when making requests
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

app.use(session({
	secret: process.env.SECRET,
	resave: false,
	saveUninitialized: true
}));

app.use(express.json());

// http://expressjs.com/en/starter/static-files.html
app.use('/static', express.static('public'));

//console.log(process.env);

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, rsp) => {
  	rsp.sendFile(__dirname + '/views/index.html');
});

app.post('/login', (req, rsp) => {
	identityServices.validateUsernamePassword(req, rsp);
});

app.get('/logout', (req, rsp) => {
	req.session.destroy();
  	rsp.json({"authenticated": false});
});

app.get('/me', (req, rsp) => {
	identityServices.sendUserResponse(req, rsp);
});

app.post('/deleteRegistration', (req, rsp) => {
	identityServices.deleteRegistration(req, rsp);
});

app.post('/attestation/options', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,true,false);
});

app.post('/attestation/result', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,false,false);
});

app.post('/assertion/options', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,true,true);
});

app.post('/assertion/result', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,false,false);
});

app.post('/assertion/login', (req, rsp) => {
	identityServices.validateFIDO2Login(req,rsp);
});


// listen for requests
if (process.env.LOCAL_SSL_SERVER) {
	https.createServer({
	    key: fs.readFileSync('./isamfido2demorp.key.pem'),
	    cert: fs.readFileSync('./isamfido2demorp.crt.pem')
	}, app)
	.listen(process.env.LOCAL_SSL_PORT, function() {
	  	console.log('Your SSL app is listening on port ' + process.env.LOCAL_SSL_PORT);
	});
} else {
	const listener = app.listen(process.env.PORT, function() {
	  	console.log('Your app is listening on port ' + listener.address().port);
	});
}
