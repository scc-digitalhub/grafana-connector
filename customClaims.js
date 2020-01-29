/**
 * DEFINE YOUR OWN CLAIM MAPPING HERE
 * TO BE PUT IN AAC CONFIG OF GRAFANA CLIENT APP
**/
function claimMapping(claims) {
    // extract roles
    var path = 'components/';
    var roles = claims.roles.filter(function(r) {
            return r.indexOf(path) == 0;
        })
        .map(function(r) {
            var subrole = r.substring(path.length);
            var a = subrole.split(':');
            return {
                org: a[0].replace(/\//g, '_').replace(/\./, '_'),
                role: a[1]
            }
        })
        .reduce(function(prev, curr) {
            if(curr.role === 'ROLE_PROVIDER')
                prev[curr.org] = 'Admin';
            else if(curr.role === 'Editor' && prev[curr.org]  !== 'Admin')
                prev[curr.org] = 'Editor';
            else if(!prev[curr.org])
                prev[curr.org] = 'Viewer';
            
            return prev;
        }, {});
    claims.grafana_roles = roles;
    return claims;
}
