var jwt = require('jsonwebtoken');
var axios = require('axios');
var randomStr = require('randomstring');
var jwksClient = require('jwks-rsa-promisified');

var JWKS_URI = process.env.AAC_JWKURL;
var ISSUER = process.env.AAC_ISSUER
var CLIENT_ID = process.env.AAC_CLIENT_ID;
var CLIENT_SECRET = process.env.AAC_CLIENT_SECRET;
var AUTH = 'Basic ' + Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET, 'utf8').toString('base64');

var GRAFANA_ENDPOINT = process.env.GRAFANA_ENDPOINT;
var GRAFANA_AUTH_USERNAME = process.env.GRAFANA_AUTH_USERNAME;
var GRAFANA_AUTH_PASSWORD = process.env.GRAFANA_AUTH_PASSWORD;
var GRAFANA_AUTH = 'Basic ' + Buffer.from(GRAFANA_AUTH_USERNAME + ':' + GRAFANA_AUTH_PASSWORD, 'utf8').toString('base64');

var CUSTOMCLAIM_ROLES = 'grafana/roles'

/**
* Check JWT token is present, is valid with respect to the preconfigured JWKS, and is not expired.
* If the check is passed, then return extracted claims.
*/

async function retrieveKey(kid) {
    try {
        console.log("Retrieving Key...")
        var client = jwksClient({
            jwksUri: JWKS_URI
        });
        const key = await client.getSigningKeyAsync(kid);
        return key.publicKey || key.rsaPublicKey;
    } catch (err) {
        console.log(err.message);
        return err
    }
}

function getKid(token) {
    try {
        console.log("Getting Kid...");
        var decoded = jwt.decode(token, { complete: true });
        console.log(decoded.header);
        return decoded.header.kid;
    } catch (err) {
        console.log("Error getting kid: " + err.message);
        return err;
    }
}

function extractAuth(headers) {
    try {
        var authorization = Object.keys(headers).includes("Authorization") ? headers["Authorization"] : headers["authorization"];
        if (authorization && authorization.startsWith("Basic ")) {
            return authorization.substring(authorization.indexOf(' ') + 1);
        } else {
            return null;
        }
    } catch (err) {
        console.log(err.message)
        return null;
    }
}

async function extractClaims(body, logger) {
    try {
        if (body) {
            var js = JSON.parse(body);
            var token = js.access_token;
            var kid = getKid(token);
            var key = await retrieveKey(kid);
            var options = { audience: CLIENT_ID, issuer: ISSUER };
            var dec = await jwt.verify(token, key, options);
            return dec;
        } else {
            return null;
        }
    } catch (err) {
        logger.error(err.message)
        return null;
    }
}

async function preProvision(claims, logger) {
    try {
        // extract roles
        logger.infoWith('Roles from AAC for Grafana: ', claims[CUSTOMCLAIM_ROLES]);
        var name = claims.username;
        var username = claims.email;
        var roles = claims[CUSTOMCLAIM_ROLES];
        if (roles != undefined) {
            // create the global user, the organizations and assing the proper roles to the user
            await provisionEntities(name, username, roles, logger);
            return roles;
        } else {
            return null;
        }
    } catch (err) {
        return err;
    }
}
/**
 * Check if the organization exists in order to provision it and assign the proper rights to the user
 * if not, create the organization
 */
async function handleOrganizations(org, role, username, userId, defaultOrg, logger) {
    var orgId = -1;
    try {
        orgId = await getOrganization(org, logger);
        if (orgId == -1) {
            orgId = await createOrganization(org, logger);
        }
        logger.info("organization " + org + " Id: " + orgId);
        // assign the proper role to the user inside the organization
        await handleUserRoles(orgId, username, userId, role, logger);
        // assign the default org of the user
        if (defaultOrg)
            await updateUser(userId, orgId, logger);
        return orgId;
    } catch (err) {
        return null;
    }
};


async function getOrganization(org, logger) {
    var orgId = -1;
    logger.info("Get organization " + org);
    try {
        var res = await axios.get(GRAFANA_ENDPOINT + '/api/orgs/name/' + org, { headers: { 'Authorization': GRAFANA_AUTH } })
        orgId = res.data.id;
        return orgId;
    } catch (err) {
        logger.errorWith('Error while getting organization: ' + org, err.message);
        return orgId;
    }
}

async function createOrganization(org, logger) {
    var orgId = -1;
    logger.info("Creating organization " + org);
    try {
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/orgs', { name: org }, { headers: { 'Authorization': GRAFANA_AUTH } })
        orgId = res.data.orgId;
        return orgId;
    } catch (err) {
        logger.errorWith('Error while creating organization: ' + org, err);
        return orgId;
    }
}

/**
 * Create the global user 
 */
async function provisionEntities(name, useremail, roles, logger) {
    var passw = randomStr.generate(8);
    var objToBeSent = { name: name, email: useremail, password: passw };
    var userId = -1;
    var iter = 0;
    logger.infoWith("Handling User creation:" + name + " with username: " + useremail);
    userId = await getUser(useremail, logger);
    // create user
    if (userId == -1) {
        userId = await createUser(name, useremail, logger);
    }
    // remove the user from old orgs
    await removeUserFromOrg(userId, roles, logger);
    // provisioning organizations
    for (var org in roles) {
        logger.info('Inside loop of orgs : ' + org + " " + roles[org]);
        roleName = roles[org];
        await handleOrganizations(org, roleName, useremail, userId, iter == Object.keys(roles).length - 1, logger);
        iter++;
    }
};

/**
 * Update user to switch its context to the given organization
 */
async function updateUser(userId, orgId, logger) {
    logger.info("Updating the default org of user " + userId + ". OrgId: " + orgId + " " + GRAFANA_ENDPOINT + '/api/users/' + userId + '/using/' + orgId);
    try {
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/users/' + userId + '/using/' + orgId, {}, { headers: { 'Authorization': GRAFANA_AUTH } })
        logger.info('User ' + userId + ' context switched successfully to orgId: ' + orgId);
        return res.data
    } catch (err) {
        logger.errorWith('Error while updating user: ' + userId, err);
    }
}

/**
 * Get user configuration
 */
async function getUser(useremail, logger) {
    var userId = -1;
    logger.info("Get user " + useremail + " " + GRAFANA_ENDPOINT + '/api/users/lookup?loginOrEmail=' + useremail);
    try {
        var res = await axios.get(GRAFANA_ENDPOINT + '/api/users/lookup?loginOrEmail=' + useremail, { headers: { 'Authorization': GRAFANA_AUTH } })
        return res.data.id;
    } catch (err) {
        logger.error('Error getting user ' + useremail + " " + err.response.data.message);
        return userId;
    }
}

/**
 * Create user
 */
async function createUser(name, useremail, logger) {
    var userId = -1;
    var passw = randomStr.generate(8);
    var objToBeSent = { name: name, email: useremail, password: passw };
    logger.info("Creating user " + name + " " + useremail);
    try {
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/admin/users', objToBeSent, { headers: { 'Authorization': GRAFANA_AUTH } })
        return res.data.id
    } catch (err) {
        logger.errorWith('Error while creating user: ' + name + " " + err.response.data.message);
        return userId;
    }
}

/**
 * Get the list of organizations in Grafana
 */
async function getListOrgsOfUser(userId, logger) {
    var orgs = [];
    try {
        var res = await axios.get(GRAFANA_ENDPOINT + '/api/users/' + userId + '/orgs', { headers: { 'Authorization': GRAFANA_AUTH } });
        logger.infoWith("List of user's organizations: ", res.data)
        return res.data

    } catch (err) {
        logger.error('Error during updating role of user: ' + err.response.data.message);
        return orgs;
    }
}

/**
 * Remove the user from the non-belonging organizations 
 */
async function removeUserFromOrg(userId, roles, logger) {
    orgs = await getListOrgsOfUser(userId, logger);
    logger.infoWith("List of user roles ", Object.keys(roles))
    excludedOrgs = orgs.filter(value => !Object.keys(roles).includes(value.name))
    logger.infoWith("List of organizations to delete the user from: ", excludedOrgs)
    try {
        for (var currOrg in excludedOrgs) {
            await axios.delete(GRAFANA_ENDPOINT + '/api/orgs/' + excludedOrgs[currOrg]["orgId"] + '/users/' + userId, { headers: { 'Authorization': GRAFANA_AUTH } })
                .catch(err => { logger.info('Error while removing user from Org. ' + excludedOrgs[currOrg]["orgId"] + " " + err.response.data.message); })
        }
    } catch (err) {
        logger.error('Error while removing user from Org.' + err.response.data.message);
    }
}

/**
 *  Assign the user to the proper role (Admin, Editor, Viewer)
 */
async function handleUserRoles(orgId, username, userId, roleName, logger) {
    logger.infoWith("Handling Roles of user:" + username + " " + userId + " in organizationId. " + orgId);
    try {
        var res = await addUserRole(orgId, username, userId, roleName, logger);
        if (res == -1) {
            logger.info('User is already member of this organization. Setting the new role to the organization ' + orgId);
            objToBeSent = { "role": roleName };
            res = await axios.patch(GRAFANA_ENDPOINT + '/api/orgs/' + orgId + '/users/' + userId, objToBeSent, { headers: { 'Authorization': GRAFANA_AUTH } })
            return res;
        }
    } catch (err) {
        logger.error('Error during updating role of user: ' + err.response.data.message);
        return null;
    }
};

async function addUserRole(orgId, username, userId, roleName, logger) {
    var objToBeSent = { loginOrEmail: username, "role": roleName };
    logger.infoWith("Adding Roles of user:" + username + " " + userId + " in organizationId. " + orgId + ". objToBeSent ", objToBeSent);
    var res = -1;
    try {
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/orgs/' + orgId + '/users', objToBeSent, { headers: { 'Authorization': GRAFANA_AUTH } })
        logger.info('Role ' + roleName + ' in org: ' + orgId + ' successfully assigned to user: ' + username);
        return res;
    } catch (err) {
        return res;
    }
};

async function processEvent(event, logger) {
    logger.info("Inside processEvent...");
    var auth = extractAuth(event.headers)
    if (auth != AUTH) {
        throw Error("Invalid authentication");
    }
    var body = event.body.toString();
    var claims = await extractClaims(body, logger);
    if (claims == null) {
        throw Error("Invalid claims or token provided");
    }
    var roles = await preProvision(claims, logger);
    if (roles == null) {
        throw Error("Invalid roles in claims");
    }
    return roles;
}

exports.handler = function (context, event) {
    var logger = context.logger;
    processEvent(event, logger)
        .then(roles => {
            var response = new context.Response({ message: 'Roles updated' }, {}, 'application/json', 200);
            context.callback(response)
        })
        .catch(err => {
            logger.error(err);
            context.callback(new context.Response({ message: 'Call failure', err: err.message }, {}, 'application/json', 500));
        });
};
