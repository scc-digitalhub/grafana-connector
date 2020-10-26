
var jwt = require('jsonwebtoken');
var axios = require('axios');
var randomStr = require('randomstring');

var JWKS_URI                    = process.env.AACJWKURL;
var RESOURCE_ID                 = process.env.AACRESOURCEID;
var GRAFANA_ENDPOINT            = process.env.GRAFANAENDPOINT;
var GRAFANA_AUTH                = process.env.GRAFANAAUTH;
var CUSTOMCLAIM_ROLES = 'grafana/roles'

/**
* Check JWT token is present, is valid with respect to the preconfigured JWKS, and is not expired.
* If the check is passed, then return extracted claims.
*/
var extractClaims = async(context, headers, callback) => {
for (var h in headers) {
    if (h.toLowerCase() === 'authorization' && headers[h]) {
        // Expect header in the form Bearer <JWT>
        var token = headers[h].substring(headers[h].indexOf(' ')+1);
        var jwksClient = require('jwks-rsa');
        var client = jwksClient({
            jwksUri: JWKS_URI
        });
        function getKey(header, keyCallback){
            if (context.key) {
                keyCallback(null, context.key);
                return;
            }
            client.getSigningKey(header.kid, function(err, key) {
                var signingKey = key ? key.publicKey || key.rsaPublicKey : null;
                context.logger.info('New key ' + signingKey);
                if(signingKey === null)
                    context.callback(new context.Response({message: 'Missing signing key'}, {}, 'application/json', 401));
                context.key = signingKey;
                keyCallback(null, signingKey);
            });
        }
  
        var options = { audience: RESOURCE_ID };
         jwt.verify(token, getKey, options, function(err, decoded) {
            context.logger.infoWith('Verify jwt: claims: ', decoded);
            if (!decoded) {	
                context.callback(new context.Response({message: 'Incorrect signature: ' , err: err}, {}, 'application/json', 401));
            }
            callback(decoded);
        }); 
        return; 
    }
}
context.callback(new context.Response({message: 'Missing token'}, {}, 'application/json', 400));
} 

/**
 * Check if the organization exists in order to provision it and assign the proper rights to the user
 * if not, create the organization
 */
async function handleOrganizations(context, org, role, username, userId, defaultOrg) {
    var orgId = -1;
    try{
        orgId = await getOrganization(context, org);
        if(orgId == -1){
            orgId = await createOrganization(context, org);        
        }         
        context.logger.info("organization " + org + " Id: " + orgId);
        // assign the proper role to the user inside the organization
        await handleUserRoles(context, orgId, username, userId, role);
        // assign the default org of the user
        if(defaultOrg)
            await updateUser(context, userId, orgId); 
        return orgId; 
    }catch(err){
        return null;
    }
};


async function getOrganization(context, org) {
    var orgId = -1;
    context.logger.info("Get organization " + org);
    try{
        var res = await axios.get(GRAFANA_ENDPOINT + '/api/orgs/name/' + org, {headers: {'Authorization': GRAFANA_AUTH}})
        orgId = res.data.id;
        return orgId;
    } catch(err){
        context.logger.infoWith('Error while getting organization: ' + org, err.message);
        return orgId;
    }
}

async function createOrganization(context, org) {
    var orgId = -1;
    context.logger.info("Creating organization " + org);
    try{
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/orgs', {name: org}, {headers: {'Authorization': GRAFANA_AUTH}})
        orgId = res.data.orgId;
        return orgId;
    } catch(err){
        context.logger.infoWith('Error while creating organization: ' + org, err);
        return orgId;
    }
}

/**
 * Create the global user 
 */
async function provisionEntities(context, name, useremail, roles){
    var passw = randomStr.generate(8);
    var objToBeSent = {name : name, email : useremail, password : passw};
    var userId = -1;
    var iter = 0;
    context.logger.infoWith("Handling User creation:" + name + " with username: " + useremail);
    userId = await getUser(context, useremail);
    context.logger.info(userId);
    // create user
    if(userId == -1){
        userId = await createUser(context, name, useremail);
    }    
    // remove the user from old orgs
    await removeUserFromOrg(context, userId, roles);
    // provisioning organizations
    for (var org in roles) {
        context.logger.info('Inside loop of orgs : ' + org + " " + roles[org]);
        roleName = roles[org];
        await handleOrganizations(context, org, roleName, useremail, userId, iter == Object.keys(roles).length-1);
        iter++;
    } 
};

/**
 * Update user to switch its context to the given organization
 */
async function updateUser (context, userId, orgId) {
    context.logger.info("Updating the default org of user " + userId + ". OrgId: " + orgId + " " + GRAFANA_ENDPOINT + '/api/users/' + userId + '/using/' + orgId);
    try{
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/users/' + userId + '/using/' + orgId, {}, {headers: {'Authorization': GRAFANA_AUTH}})
        context.logger.info('User ' + userId + ' context switched successfully to orgId: ' + orgId);
        return res.data
    } catch(err){
        context.logger.infoWith('Error while updating user: ' + userId, err);
    }
}

/**
 * Get user configuration
 */
async function getUser (context, useremail) {
    var userId = -1;
    context.logger.info("Get user " + useremail + " " + GRAFANA_ENDPOINT + '/api/users/lookup?loginOrEmail=' + useremail);
    try{
        var res = await axios.get(GRAFANA_ENDPOINT + '/api/users/lookup?loginOrEmail=' + useremail, {headers: {'Authorization': GRAFANA_AUTH}})
        return res.data.id;
    } catch(err){
        context.logger.info('Error getting user ' + useremail + " " + err.response.data.message);
        return userId;
    }
}

/**
 * Create user
 */
async function createUser (context, name, useremail) {
    var userId = -1;
    var passw = randomStr.generate(8);
    var objToBeSent = {name : name, email : useremail, password : passw};
    context.logger.info("Creating user " + name + " " + useremail );
    try{
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/admin/users', objToBeSent, {headers: {'Authorization': GRAFANA_AUTH}})
        return res.data.id
    } catch(err){
        context.logger.infoWith('Error while creating user: ' + name, err.response.data.message);
        return userId;
    }
}

/**
 * Get the list of organizations in Grafana
 */
async function getListOrgsOfUser (context, userId) {
    return axios.get(GRAFANA_ENDPOINT + '/api/users/' + userId + '/orgs', {headers: {'Authorization': GRAFANA_AUTH}})
        .then(function(res){
            context.logger.info("List of user's organizations: ")
            console.log(res.data)
            return res.data
        })
}

/**
 * Remove the user from the non-belonging organizations 
 */
async function removeUserFromOrg (context, userId, roles) {
    orgs = await getListOrgsOfUser(context, userId);
    console.log(Object.keys(roles))
    excludedOrgs = orgs.filter(value => !Object.keys(roles).includes(value.name))
    context.logger.info("List of organizations to delete the user from: ")
    console.log(excludedOrgs)
    try{
        for(var currOrg in excludedOrgs){
            context.logger.info(GRAFANA_ENDPOINT + '/api/orgs/' + excludedOrgs[currOrg]["orgId"] + '/users/' + userId)
            await axios.delete(GRAFANA_ENDPOINT + '/api/orgs/' + excludedOrgs[currOrg]["orgId"] + '/users/' + userId, {headers: {'Authorization': GRAFANA_AUTH}})
        }   
    } catch(err){
        context.logger.infoWith('Error while removing user from Org.', err);
    }
}

/**
 *  Assign the user to the proper role (Admin, Editor, Viewer)
 */
async function handleUserRoles (context, orgId, username, userId, roleName) {
    context.logger.infoWith("Handling Roles of user:" + username + " " + userId + " in organizationId. " + orgId);
    try{
        var res = await addUserRole(context, orgId, username, userId, roleName);
        if(res == -1){
            context.logger.info('User is already member of this organization. Setting the new role to the organization ' + orgId);
            objToBeSent = {"role" : roleName};
            res = await axios.patch(GRAFANA_ENDPOINT + '/api/orgs/' + orgId + '/users/' + userId, objToBeSent, {headers: {'Authorization': GRAFANA_AUTH}})
            return res;
        }
    }catch(err){
        context.logger.info('Error during updating role of user: ' + err.response.data.message);
        return null;
    }
};

async function addUserRole (context, orgId, username, userId, roleName) {
    var objToBeSent = {loginOrEmail : username, "role" : roleName};
    context.logger.infoWith("Adding Roles of user:" + username + " " + userId + " in organizationId. " + orgId + ". objToBeSent " , objToBeSent);
    var res = -1;
    try{
        var res = await axios.post(GRAFANA_ENDPOINT + '/api/orgs/' + orgId + '/users', objToBeSent, {headers: {'Authorization': GRAFANA_AUTH}})
        context.logger.info('Role ' + roleName + ' in org: ' + orgId + ' successfully assigned to user: ' + username);
        return res;
    }catch(err){
        return res;
    }
};

exports.handler = function(context, event) {
    extractClaims(context, event.headers, async function(claims) {
        try{
            // extract roles
            context.logger.infoWith('Roles from AAC for Grafana: ', claims[CUSTOMCLAIM_ROLES]);
            var name  = claims.username;
            var username = claims.email;  
            var roles = claims[CUSTOMCLAIM_ROLES];       
            if(roles != undefined){
                // create the global user, the organizations and assing the proper roles to the user
                await provisionEntities(context, name, username, roles);
                context.callback(roles);
            } else{
                context.callback(new context.Response({message: 'Missing roles from AAC. Check the claim mapping'}, {}, 'application/json', 500));
            } 
        } catch(err){
            context.callback(new context.Response({message: 'GRAFANA call failure', err: err}, {}, 'application/json', 500));
        }      
    });
};

