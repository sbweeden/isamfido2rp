//
// OAuthTokenManager - performs client_credentials flow as necessary to get an OAuth token
// and execute a function with that token.
//
const request = require('request');

var tokenResponse = null;

function executeWithAccessToken(f) {
	// if the current access token has more than two minutes to live, use it, otherwise get a new one
	var now = new Date();

	if (tokenResponse != null && tokenResponse.expires_at_ms > (now.getTime() + (2*60*1000))) {
		//console.log("Using access token: " + tokenResponse.access_token);
		f(tokenResponse.access_token);
	} else {
		getNewAccessToken(f);
	}
}

function getNewAccessToken(f) {
	var options = {
		url: process.env.OAUTH_TOKEN_ENDPOINT,
		method: "POST",
		headers: {
			"Accept": "application/json",
		},
		form: {
			"grant_type": "client_credentials",
			"client_id": process.env.OAUTH_CLIENT_ID,
			"client_secret": process.env.OAUTH_CLIENT_SECRET
		}
	};
	request(options, (err, rsp, body) => {
		var access_token = null;
		if (err == null && rsp != null && rsp.statusCode == 200) {
			tokenResponse = JSON.parse(body);
			// compute this
			var now = new Date();
			tokenResponse.expires_at_ms = now.getTime() + (tokenResponse.expires_in * 1000);
			access_token = tokenResponse.access_token;
		} else {
			console.log("unable to get access token");
		}
		//console.log("Using access token: " + access_token);
		f(access_token);
	});
}

module.exports = { 
	executeWithAccessToken: executeWithAccessToken 
};
