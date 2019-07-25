//
// fido2services - performs user and FIDO2 operations against ISAM
//
const requestp = require('request-promise-native');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');

/**
* Ensure the request contains a "username" attribute, and make sure it's either the
* empty string (if allowed), or is the username of the currently authenticated user. 
*/
function validateSelf(fidoRequest, username, allowEmptyUsername) {

	if (username != null) {
		if (!((fidoRequest.username == username) || (allowEmptyUsername && fidoRequest.username == ""))) {
			throw new fido2error.fido2Error("Invalid username in request");
		}
	} else {
		// no currently authenticated user
		// only permitted if fidoRequest.username is the empty string and allowEmptyUsername
		if (!(fidoRequest.username == "" && allowEmptyUsername)) {
			throw new fido2error.fido2Error("Not authenticated");
		}
	}

	return fidoRequest;
}

function handleErrorResponse(methodName, rsp, e, genericError) {
	// log what we can about this error case
	console.log("isamservices." + methodName + " e: " + 
		e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));

	// if e is already a fido2Error, return it, otherwise return a generic error message
	rsp.json((e != null && e.status == "failed") ? 
		e : new fido2error.fido2Error(genericError));
}

function rethrowRequestError(methodName, e, genericError) {
	console.log("rethrowing isamservices." + methodName + " e: " + 
		e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	var errMsg = genericError;
	if (e != null && e.error != null && e.error.errorMessage != null) {
		errMsg = e.error.errorMessage;
	}
	throw new fido2error.fido2Error(errMsg);
}

/**
* Calls the ISAM apiauthsvc to validate username/password
*/
function validateUsernamePassword(req ,rsp) {
	var username = req.body.username;
	var password = req.body.password;
	if (username != null && password != null) {
		requestp({
			url: process.env.ISAM_APIAUTHSVC_ENDPOINT,
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json"
			},
			json: true,
			body: {
				"PolicyId" : "urn:ibm:security:authentication:asf:password",
				"operation": "verify",
				"username": username,
				"password": password
			},
			resolveWithFullResponse: true
		}).then((authResponse) => {
			if (authResponse != null && authResponse.statusCode == 204) {
				// pwd check worked - finish login and return registrations
				req.session.username = username;
				return getUserResponse(req);
			} else {
				// throw an error. If we have an apiauthsvc response with an error message, use it, otherwise send a generic error message
				throw new fido2error.fido2Error(
						(authResponse != null && authResponse.body != null && authResponse.body.message != null) ? 
							authResponse.body.message : "Invalid credentials");
			}
		}).then((userResponse) => {
			rsp.json(userResponse);
		}).catch((e) => {
			handleErrorResponse("validateUsernamePassword", rsp, e, "Unable to validate username and password - see server log for details");
		});
	} else {
		rsp.json(new fido2error.fido2Error("Invalid username and password"));
	}
}

/**
* Proxies what is expected to be a valid FIDO2 server request to one of:
* /attestation/options
* /attestation/result
* /assertion/options
* /assertion/result
*
* to the ISAM server. There is little validation done other than to ensure
* that the client is not sending a request for a user other than the user
* who is currently logged in.
*/
function proxyFIDO2ServerRequest(req, rsp, validateUsername, allowEmptyUsername) {

	var bodyToSend = validateUsername ? validateSelf(req.body, req.session.username, allowEmptyUsername) : req.body;
	return tm.getAccessToken()
	.then((access_token) => {
		return requestp({
			url: process.env.ISAM_FIDO2_ENDPOINT_PREFIX + req.url,
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true,
			body: bodyToSend
		});
	}).then((fido2Response) => {
		rsp.json(fido2Response);
	}).catch((e) => {
		handleErrorResponse("proxyFIDO2ServerRequest", rsp, e, "Unable to proxyFIDO2ServerRequest - see server log for details");
	});
}

/**
* Performs an assertion result to the FIDO2 server, and if successful, completes
* the login process.
*/
function validateFIDO2Login(req, rsp) {
	var access_token = null;
	return tm.getAccessToken()
	.then((at) => {
		access_token = at;
		return requestp({
			url: process.env.ISAM_FIDO2_ENDPOINT_PREFIX + "/assertion/result",
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true,
			body: req.body
		}).catch((e) => {
			rethrowRequestError(validateFIDO2Login, e, "Unable to validate fido2 login - see server log for details");
		});
	}).then((assertionResult) => {
		if (assertionResult.status == "ok") {
			req.session.username = assertionResult.user.name;
			return getUserResponse(req);
		} else {
			throw fido2Error(assertionResult.errorMessage ? assertionResult.errorMessage : "Error communicating with FIDO2 server");
		}
	}).then((userResponse) => {
		rsp.json(userResponse);
	}).catch((e) => {
		handleErrorResponse("validateFIDO2Login", rsp, e, "Unable to validate fido2 login - see server log for details");
	});
}

function coerceSCIMResultToUserResponse(req, scimResult) {
	if (scimResult.totalResults == 1) {
		// use this opportunity to store the SCIM id in session as well
		req.session.userSCIMId = scimResult.Resources[0].id;

		var result = {
			"authenticated": true,
			"username": req.session.username,
			"credentials": []
		};

		var fido2RegistrationsSchema = scimResult.Resources[0]["urn:ietf:params:scim:schemas:extension:isam:1.0:FIDO2Registrations"];
		if (fido2RegistrationsSchema != null) {
			var fido2Registrations = fido2RegistrationsSchema["fido2registrations"];
			if (fido2Registrations != null) {
				result.credentials = fido2Registrations;
			}
		}

		return result;
	} else {
		throw new fido2error.fido2Error("Unable to get SCIM data for user: " + username);
	}
}

function getUserResponse(req) {
	var access_token = null;
	return tm.getAccessToken()
	.then((at) => {
		access_token = at;
		return requestp({
			url: process.env.ISAM_SCIM_ENDPOINT_PREFIX + "/Users",
			method: "GET",
			qs: { "filter" : "username eq " + req.session.username },
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((scimResult) => {
		return coerceSCIMResultToUserResponse(req, scimResult);
	});
}

/**
* Determines if the user is logged in.
* If so, returns their username and list of currently registered FIDO2 credentials as determined
*   from a SCIM call to ISAM. During the SCIM call to ISAM we also store the user's SCIM ID in session.
* If not returns {"authenticated":false}
*/
function sendUserResponse(req, rsp) {
	if (req.session.username) {
		tm.getAccessToken().then((at) => {
			return getUserResponse(req);
		}).then((userResponse) => {
			rsp.json(userResponse);
		}).catch((e) => {
			handleErrorResponse("sendUserResponse", rsp, e, "Unable to get and send user response - see server log for details");
		});
	} else {
		rsp.json({"authenticated": false});
	}
}

/**
* Uses a SCIM PATCH operation to delete the provided credentialId for the user.
* Returns the remaining registered credentials in the same format as sendUserResponse
*/
function deleteRegistration(req, rsp) {
	if (req.session.username) {
		var credentialId = req.body.credentialId;
		if (credentialId != null) {
			var access_token = null;
			tm.getAccessToken().then((at) => {
				access_token = at;
				return requestp({
					url: process.env.ISAM_SCIM_ENDPOINT_PREFIX + "/Users/" + req.session.userSCIMId,
					method: "PATCH",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true,
					body: {
					    "schemas": [
					        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
					    ],
					    "Operations": [
					        {
					          "op": "remove",
					          "path": "urn:ietf:params:scim:schemas:extension:isam:1.0:FIDO2Registrations:fido2registrations[credentialId eq " 
					          	+ credentialId + "]",
					        }
					    ]
					}
				});
			}).then((scimResult) => {
				return coerceSCIMResultToUserResponse(req, scimResult);
			}).then((userResponse) => {
				rsp.json(userResponse);
			}).catch((e) => {
				handleErrorResponse("deleteRegistration", rsp, e, "Unable to delete registration - see server log for details");
			});


		} else {
			rsp.json(new fido2Error("Invalid credentialId"));	
		}
	} else {
		rsp.json(new fido2Error("Not logged in"));
	}
}


module.exports = { 
	validateUsernamePassword: validateUsernamePassword,
	sendUserResponse: sendUserResponse, 
	deleteRegistration: deleteRegistration,
	proxyFIDO2ServerRequest: proxyFIDO2ServerRequest,
	validateFIDO2Login: validateFIDO2Login
};
