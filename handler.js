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
var handleOrganizations = async (context, org, role, username, userId) => {
    var org_calls        = [];
    var orgId            = "";
    
    org_calls.push( axios.get(GRAFANA_ENDPOINT + '/api/orgs/name/' + org, {headers: {'Authorization': GRAFANA_AUTH}})
        .then(function(res) {
            context.logger.info('Organization ' + org + ' already exists in Grafana.', res);
            orgId = res.data.id;            
            context.logger.info("organization Id: " + orgId);
            
            // assign the proper role to the user inside the organization
            handleUserRoles(context, orgId, username, userId, role);
        }).catch(function(err) {
            return axios.post(GRAFANA_ENDPOINT + '/api/orgs', {name: org}, {headers: {'Authorization': GRAFANA_AUTH}})
                        .then(function(res) {
                            context.logger.info('Organization does not exist in Grafana.Creating organization: ' + org);
                            orgId = res.data.orgId;
                            context.logger.info("organization Id: " + orgId);
                            
                            // assign the proper role to the user inside the organization
                            handleUserRoles(context, orgId, username, userId, role);
                            org_calls.push('Organization does not exist in Grafana.Creating organization: ' + org);
                            return 'Organization does not exist in Grafana.Creating organization: ' + org;
                        }).catch(function(err) {
                            context.logger.info('Error while creating organization: ' + org + " " + err);
                            context.callback(new context.Response({message: 'GRAFANA call failure: ' + 'Error while creating organization: ' + org + " ", err: err}, {}, 'application/json', 500));                            
                        }); 
        })
    );
    return org_calls;    
};
/**
 * Create the global user 
 */
var provisionEntities = async (context, name, useremail, roles) => {
    var passw = randomStr.generate(8);
    var objToBeSent = {name : name, email : useremail, password : passw};
    var userId = 0;
    context.logger.infoWith("Handling User creation:" + name + " with username: " + useremail);
    userId = await axios.get(GRAFANA_ENDPOINT + '/api/users/lookup?loginOrEmail=' + useremail, {headers: {'Authorization': GRAFANA_AUTH}})
        .then(function(res){
            context.logger.info('Global user ' + name + ' ' + useremail + ' already exists in Grafana.', res);
            userId = res.data.id;
            // remove the user from old orgs
            removeUserFromOrg(context, userId, roles);
            // provisioning organizations
            for (var org in roles) {
                context.logger.info('Inside loop of orgs : ' + org + " " + roles[org]);
                roleName = roles[org];
                handleOrganizations(context, org, roleName, useremail, userId);
            }         
        }).catch(function(err){
            axios.post(GRAFANA_ENDPOINT + '/api/admin/users', objToBeSent, {headers: {'Authorization': GRAFANA_AUTH}})
                .then(function(res) {
                    context.logger.info('User ' + name + ' successfully created in Grafana.');
                    userId = res.data.id;
                    // remove the user from old orgs
                    removeUserFromOrg(context, userId, roles);
                    // provisioning organizations
                    for (var org in roles) {
                        context.logger.info('Inside loop of orgs : ' + org + " " + roles[org]);
                        roleName = roles[org];
                        handleOrganizations(context, org, roleName, useremail, userId);
                    } 
                    return res.data.id;
                }).catch(function(err) {
                        context.logger.info('Error while creating user: ' + name + err);
                        context.callback(new context.Response({message: 'GRAFANA call failure: ' + 'Error while creating user: ' + name, err: err}, {}, 'application/json', 500));                            
                });
        });
};
/**
 * Get the list of organizations in Grafana
 */
var getListOrgsOfUser = async (context, userId) => {
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
var removeUserFromOrg = async (context, userId, roles) => {
    orgs = await getListOrgsOfUser(context, userId);
    console.log(Object.keys(roles))
    excludedOrgs = orgs.filter(value => !Object.keys(roles).includes(value.name))
    context.logger.info("List of organizations to delete the user from: ")
    console.log(excludedOrgs)
    for(var currOrg in excludedOrgs){
        axios.delete(GRAFANA_ENDPOINT + '/api/orgs/' + excludedOrgs[currOrg]["orgId"] + '/users/' + userId, {headers: {'Authorization': GRAFANA_AUTH}})
        .then(function(res){
            context.logger.info('User ' + userId + ' removed successfully from org: ' + currOrg);
            return res.data
        }).catch(function(err){
                context.callback(new context.Response({message: 'GRAFANA call failure: ' +  'Error while removing user from Org.' + currOrg.name , err: err}, {}, 'application/json', 500));
        })
    }   
}

/**
 *  Assign the user to the proper role (Admin, Editor, Viewer)
 */
var handleUserRoles = async (context, orgId, username, userId, roleName) => {
    var objToBeSent = {loginOrEmail : username, "role" : roleName};
    context.logger.infoWith("Handling Roles of user:" + username + " in organizationId. " + orgId + ". objToBeSent " , objToBeSent);
    axios.post(GRAFANA_ENDPOINT + '/api/orgs/' + orgId + '/users', objToBeSent, {headers: {'Authorization': GRAFANA_AUTH}})
        .then(function(res) {
            context.logger.info('Role ' + roleName + ' successfully assigned to user: ' + username);
        }).catch(function(err) {
                context.logger.info('User is already member of this organization. Setting the new role to the organization ' + orgId);
                objToBeSent = {"role" : roleName};
                axios.patch(GRAFANA_ENDPOINT + '/api/orgs/' + orgId + '/users/' + userId, objToBeSent, {headers: {'Authorization': GRAFANA_AUTH}})
                    .then(function(res){
                        context.logger.info('Role ' + roleName + ' successfully assigned to user: ' + username);
                    }) .catch(function(err){
                            context.callback(new context.Response({message: 'GRAFANA call failure: ' +  'Error while assigning role ' + roleName + ' to user: ' + username, err: err}, {}, 'application/json', 500));
                    })
            });
};
exports.handler = async(context, event) => {
    extractClaims(context, event.headers, function(claims) {
        try{
            // extract roles
            context.logger.infoWith('Roles from AAC for Grafana: ', claims[CUSTOMCLAIM_ROLES]);
            var name  = claims.username;
            var username = claims.email;  
            var roles = claims[CUSTOMCLAIM_ROLES];       
            if(roles != undefined){
                // create the global user, the organizations and assing the proper roles to the user
                provisionEntities(context, name, username, roles);
                context.callback(roles);
            } else{
                context.callback(new context.Response({message: 'Missing roles from AAC. Check the claim mapping'}, {}, 'application/json', 500));
            } 
        } catch(err){
            context.callback(new context.Response({message: 'GRAFANA call failure', err: err}, {}, 'application/json', 500));
        }      
    });
};
