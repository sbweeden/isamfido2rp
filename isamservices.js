//
// fido2services - performs user and FIDO2 operations against ISAM
//
const request = require('request');
const tm = require('./oauthtokenmanager.js');

/**
* Simply wrapper for an error message
*/
function fido2Error(msg) {
	this.status = "failed";
   	this.errorMessage = msg;
}

/**
* Ensure the request contains a "username" attribute, and make sure it's either the
* empty string (if allowed), or is the username of the currently authenticated user. 
*/
function validateSelf(fidoRequest, username, allowEmptyUsername) {

	if (username != null) {
		if (!((fidoRequest.username == username) || (allowEmptyUsername && fidoRequest.username == ""))) {
			throw new fido2Error("Invalid username in request");
		}
	} else {
		// no currently authenticated user
		// only permitted if fidoRequest.username is the empty string and allowEmptyUsername
		if (!(fidoRequest.username == "" && allowEmptyUsername)) {
			throw new fido2Error("Not authenticated");
		}
	}

	return fidoRequest;
}

/**
* Calls the ISAM apiauthsvc to validate username/password
*/
function validateUsernamePassword(req ,rsp) {
	var username = req.body.username;
	var password = req.body.password;
	if (username != null && password != null) {
		var options = {
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
			}
		};
		request(options, (err, rsp2, body) => {
			if (err == null && rsp2 != null && rsp2.statusCode == 204) {
				// login worked - send back user response
				req.session.username = username;
				sendUserResponse(req, rsp);
			} else if (err == null && rsp2 != null && rsp2.statusCode == 200 && body.message != null) {
				rsp.json(new fido2Error(body.message));
			} else {
				rsp.json(new fido2Error("Error communicating with ISAM AAC server"));
			}
		});
	} else {
		rsp.json(new fido2Error("Invalid username and password"));
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
	try {
		var bodyToSend = validateUsername ? validateSelf(req.body, req.session.username, allowEmptyUsername) : req.body;
		tm.executeWithAccessToken((access_token) => {
			if (access_token != null) {
				var options = {
					url: process.env.ISAM_FIDO2_ENDPOINT_PREFIX + req.url,
					method: "POST",
					headers: {
						"Content-type": "application/json",
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true,
					body: bodyToSend
				};
				request(options).pipe(rsp);
			} else {
				rsp.json(new fido2Error("Unable to get communicate with FIDO2 server"));
			}
		});
	} catch (errObj) {
		rsp.json(errObj);
	}
}

/**
* Performs an assertion result to the FIDO2 server, and if successful, completes
* the login process.
*/
function validateFIDO2Login(req, rsp) {
	tm.executeWithAccessToken((access_token) => {
		if (access_token != null) {
			var options = {
				url: process.env.ISAM_FIDO2_ENDPOINT_PREFIX + "/assertion/result",
				method: "POST",
				headers: {
					"Content-type": "application/json",
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				json: true,
				body: req.body
			};
			request(options, (err, rsp2, body) => {
				if (err == null && rsp2 != null && rsp2.statusCode == 200) {
					if (body.status == "ok") {
						// login worked - send back user response
						req.session.username = body.user.name;
						sendUserResponse(req, rsp);
					} else {
						rsp.json(new fido2Error(body.errorMessage ? body.errorMessage : "Error communicating with FIDO2 server"));
					}
				} else {
					rsp.json(new fido2Error("Error communicating with FIDO2 server"));
				}
			});
		} else {
			rsp.json(new fido2Error("Unable to get communicate with FIDO2 server"));
		}
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
		var result = {};
		result.authenticated = true;
		result.username = req.session.username;

		// call SCIM to get and parse credentials
		tm.executeWithAccessToken((access_token) => {
			if (access_token != null) {
				var options = {
					url: process.env.ISAM_SCIM_ENDPOINT_PREFIX + "/Users",
					method: "GET",
					qs: { "filter" : "username eq " + req.session.username },
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true
				};
				request(options, (err, rsp2, body) => {
					var credentials = [];
					if (err == null && rsp2 != null && rsp2.statusCode == 200) {
						if (body.totalResults == 1) {
							// use this opportunity to store the SCIM id in session as well
							req.session.userSCIMId = body.Resources[0].id;

							// get and return all the FIDO2 registrations
							var fido2RegistrationsSchema = body.Resources[0]["urn:ietf:params:scim:schemas:extension:isam:1.0:FIDO2Registrations"];
							if (fido2RegistrationsSchema != null) {
								var fido2Registrations = fido2RegistrationsSchema["fido2registrations"];
								if (fido2Registrations != null) {
									credentials = fido2Registrations;
								}
							}
						}
						// marshall the credentials and send result
						result.credentials = credentials;
						rsp.json(result);
					} else {
						console.log("unable to get SCIM data for user: " + req.session.username);
						rsp.json(new fido2Error("Error communicating with SCIM server"));
					}

				});
			} else {
				rsp.json(new fido2Error("Unable to communicate with SCIM server"));
			}
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
		var result = {};
		result.authenticated = true;
		result.username = req.session.username;

		var credentialId = req.body.credentialId;
		if (credentialId != null) {
			// call SCIM to get and parse credentials
			tm.executeWithAccessToken((access_token) => {
				if (access_token != null) {
					var options = {
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

					};
					request(options, (err, rsp2, body) => {
						var credentials = [];
						if (err == null && rsp2 != null && rsp2.statusCode == 200) {
							if (body.totalResults == 1) {
								// get and return all the FIDO2 registrations
								var fido2RegistrationsSchema = body.Resources[0]["urn:ietf:params:scim:schemas:extension:isam:1.0:FIDO2Registrations"];
								if (fido2RegistrationsSchema != null) {
									var fido2Registrations = fido2RegistrationsSchema["fido2registrations"];
									if (fido2Registrations != null) {
										credentials = fido2Registrations;
									}
								}
							}
							// marshall the credentials and send result
							result.credentials = credentials;
							rsp.json(result);
						} else {
							console.log("unable to update SCIM data for user: " + req.session.username);
							rsp.json(new fido2Error("Error communicating with SCIM server"));
						}
					});
				} else {
					rsp.json(new fido2Error("Unable to communicate with SCIM server"));
				}
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
