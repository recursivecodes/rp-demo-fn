# rp-demo-fn

A demonstration of using Resource Principal authentication to sign a request in an Oracle Function for use with the OCI REST API.

## Create App:

```shell script
$ fn create app rp-demo-app --annotation oracle.com/oci/subnetIds='["ocid1.subnet.oc1.phx..."]'
```

## Create Fn:

```shell script
$ fn init --runtime node rp-demo-fn
```

## Install dependencies:

```shell script
$ npm install http-signature jssha
```

## Create Fn:

See `func.js`. 
 
## Deploy Fn:

```shell script
$ fn deploy --verbose --app rp-demo-app 
```

## Invoke Fn:

```shell script
echo '{"namespace": "[your object storage namespace]", "compartmentId": "ocid1.compartment.oc1..."}' | fn invoke rp-demo-app rp-demo-fn | jq
```