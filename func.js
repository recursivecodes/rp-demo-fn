/*
*  This serverless function retrieves information
*  via the OCI REST API
*  by making signed HTTPS requests
*  using Resource Principal (RP) authentication.
*  To enable RP auth, you need to create a dynamic
*  group and assign the appropriate policies.
*  For more info, see:
*  https://docs.cloud.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsaccessingociresources.htm
*/
const fdk = require('@fnproject/fdk')
const fs = require('fs')
const https = require('https')
const httpSignature = require('http-signature')
const jsSHA = require("jssha")

fdk.handle( function(requestDetails) {

  /* read and parse Resource Principal Session Token (RPST) */
  const sessionTokenFilePath = process.env.OCI_RESOURCE_PRINCIPAL_RPST
  const rpst = fs.readFileSync(sessionTokenFilePath, {encoding: 'utf8'})

  /*
  *  get and parse the claims from the RPST
  *  https://medium.com/@ddevinda/decode-jwt-token-6c75fa9aba6f
  */
  const payload = rpst.split('.')[1]
  const buff = Buffer.from(payload, 'base64')
  const payloadDecoded = buff.toString('ascii')
  const claims = JSON.parse(payloadDecoded)

  /* get tenancy id from claims */
  const tenancyId = claims.res_tenant

  /* get the RP private key */
  const privateKeyPath = process.env.OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM
  const privateKey = fs.readFileSync(privateKeyPath, 'ascii')

  /*
  *  set the keyId used to sign the request
  *  the format here is the literal string 'ST$'
  *  followed by the entire contents of the RPST
  */
  const keyId = `ST$${rpst}`

  /*
  *  a function used to sign the request
  *  based mostly on
  *  https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm#NodeJS
  */
  function sign(request, options) {

    const headersToSign = [
      "host",
      "date",
      "(request-target)"
    ];

    const methodsThatRequireExtraHeaders = ["POST", "PUT"];

    if (methodsThatRequireExtraHeaders.indexOf(request.method.toUpperCase()) !== -1) {
      options.body = options.body || "";

      const shaObj = new jsSHA("SHA-256", "TEXT");
      shaObj.update(options.body);

      request.setHeader("Content-Length", options.body.length);
      request.setHeader("x-content-sha256", shaObj.getHash('B64'));

      headersToSign = headersToSign.concat([
        "content-type",
        "content-length",
        "x-content-sha256"
      ]);
    }

    httpSignature.sign(request, {
      key: options.privateKey,
      keyId: keyId,
      headers: headersToSign
    });

    const newAuthHeaderValue = request.getHeader("Authorization").replace("Signature ", "Signature version=\"1\",");
    request.setHeader("Authorization", newAuthHeaderValue);
  }

  /* return a promise that contains the REST API call */
  return new Promise((resolve, reject) => {

    /* the domain/path for the REST endpoint */
    const requestOptions = {
      host: 'objectstorage.us-phoenix-1.oraclecloud.com',
      path: `/n/${encodeURIComponent(requestDetails.namespace)}/b/?compartmentId=${encodeURIComponent(requestDetails.compartmentId)}`,
    };

    /* the request itself */
    const request = https.request(requestOptions, (res) => {
      let data = ''

      res.on('data', (chunk) => {
        data += chunk
      });

      res.on('end', () => {
        resolve(JSON.parse(data))
      });

      res.on('error', (e) => {
        console.error(e)
        reject(JSON.parse(e))
      });
    })

    /* sign the request using the private key, tenancy id and the keyId (see above) */
    sign(request, {
      privateKey: privateKey,
      tenancyId: tenancyId,
      keyId: keyId,
    })

    request.end()
  })
})
