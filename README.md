# Serverless Grafana connector for organization and user provisioning

This example demonstrates how to use Grafana Single Sign-On with [AAC](https://github.com/scc-digitalhub/AAC) and serverless.

## AAC Client Application Configuration

For roles list  elaboration it is important to put the content of the file customClaims.js in the section Custom Claim Mapping Function of the Grafana Client App.
Make sure to change the value of the path 'components/' according to the needs of the Grafana component including also the customization of the role names corresponding to Grafana roles.


