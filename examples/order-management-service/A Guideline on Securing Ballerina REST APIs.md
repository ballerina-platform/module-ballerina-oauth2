# Secured Order Management Service with OAuth2

[![Star on Github](https://img.shields.io/badge/-Star%20on%20Github-blue?style=social&logo=github)](https://github.com/ballerina-platform/module-ballerina-oauth2)

_Authors_: @ldclakmal \
_Reviewers_: @shafreenAnfar \
_Created_: 2022/09/03 \
_Updated_: 2023/04/24

## Overview

This guide explains how to secure an 'Order Management Service' (RESTful service) with OAuth2 using Ballerina. 
The following figure illustrates a high-level design diagram of the complete use case.

![Securing Microservice with OAuth2](./order-management-service.png)

The end-user (customer), in this example, Alice and Bob, interacts with the system using the web/mobile app provided.
This web/mobile app acts as a 'Client' on behalf of the user’s actions and calls to the 'API Gateway'. The 'API Gateway' 
routes the requests to 'Order Service', which is responsible for processing the order for the customer. The 'Inventory 
Service' is called by the 'Order Service' to process the inventory-related operations.

**NOTE**: For this guide, since we are discussing the OAuth2 security aspects, we are focussing on the network 
interactions until the 'API Gateway' validates a request.

Scenario 1 - Web App:
- The end-user 'Alice' wants to retrieve her order details using the web app.
- First, she signs in to the application with her credentials (username and password).
- Now the web app needs to invoke an API on behalf of the logged-in end-user 'Alice'. It talks to the 'OAuth 
  Authorization Server', trusted by the API, and uses the client credentials grant type, to get an access token.
- Now the web app invokes the API with the access token.
- The 'API Gateway' intercepts the request from the end-user, extracts the token, and then talks to the 'OAuth
  Authorization Server' connected to validate the token.

Scenario 2 - Mobile App:
- The end-user 'Bob' wants to retrieve her order details using the web app.
- The end-user 'Bob' sign-in to the mobile app using the single sign-on (SSO) feature provided.
- The end-user gets redirected to the OpenID Connect (OIDC) server and authenticates against the user-store or 
  active-directory connected to it. After the authentication, the end-user gets redirected back to the mobile app, with 
  an authorization code (assuming that we are using OAuth 2.0 authorization code grant type).
- The mobile app talks directly to the OpenID Connect (OIDC) server and exchanges the authorization code from the 
  previous step to an ID token, and an access token. The ID token itself is a JWT, which is signed by the OpenID Connect 
  (OIDC) server.
- Now the mobile app needs to invoke an API on behalf of the logged-in end-user 'Bob'. It talks to the 'OAuth 
  Authorization Server', trusted by the API, and using the JWT grant type, exchanges the received JWT (ID token) to an 
  access token. The 'OAuth Authorization Server' validates the JWT and makes sure that it’s being signed by a trusted 
  identity provider. In this case, the 'OAuth Authorization Server' trusts the OpenID Connect (OIDC) identity provider.
- Now the mobile app invokes the API with the access token.
- The 'API Gateway' intercepts the request from the end-user, extracts the token, and then talks to the 'OAuth
  Authorization Server' connected to validate the token.

## Implementation

**NOTE**: To get started with the implementation we need to have the web/mobile app to be ready. But, since we are
discussing the OAuth2 security aspects by this guide, the frontend implementation of the web/mobile app is not 
explained. We will be using Ballerina as the app backend of both web/mobile app (hereinafter referred to as 'Web Client 
Backend' and 'Mobile Client Backend').

- Now, we can get started with the 'Web Client Backend', which is responsible to invoke an API on behalf of the 
  logged-in end-user. It talks to the 'OAuth Authorization Server', trusted by the API, and uses the client credentials 
  grant type, to get an access token.
  
- The client authentication is enabled by setting the `auth` client configuration of the Ballerina HTTP client. It is 
  configured with the client credentials grant configurations so that the Ballerina HTTP client knows how to get the 
  access token and proceed with the actual API call.
  Refer to [`examples/order-management-service/app_backend`](./app_backend) for the implementation.

- Now, we can get started with the 'Mobile Client Backend', which is also responsible to invoke an API on behalf of 
  the logged-in end-user. It talks to the 'OAuth Authorization Server', trusted by the API, and using the JWT grant 
  type, exchanges the received JWT (ID token) to an access token. The 'OAuth Authorization Server' validates the JWT 
  and makes sure that it’s being signed by a trusted identity provider. In this case, the 'OAuth Authorization Server' 
  trusts the OpenID Connect (OIDC) identity provider.

- The client authentication is enabled by setting the `auth` client configuration of the Ballerina HTTP client. It is
  configured with the JWT bearer grant configurations so that the Ballerina HTTP client knows how to get the access 
  token and proceed with the actual API call.
  Refer to [`examples/order-management-service/app_backend`](./app_backend) for the implementation.
  
- Now, we can get started with the 'API Gateway', which is responsible to authorize the requests using OAuth2 and 
  forward the request to the actual microservice via mTLS (mutual TLS). In this scenario, it is 'Order Service'. The 
  'API Gateway' service is secured by setting the `auth` attribute of `http:ServiceConfig` with the OAuth2 introspection 
  configurations, so that the Ballerina HTTP service knows how to validate the access token with the configured 'OAuth 
  Authorization Server'. Once validated, the business logic defined inside the resource will get executed. In this case, 
  it will call the 'Order Service' via mTLS and return the response to the 'Client'.
  
**NOTE**: For the simplicity of the article, since we are interested only in OAuth2 security aspects the rest of the 
components like 'Order Service' and 'Inventory Service' is not implemented. But, to complete the story, we 
will be returning a successful mock response from the 'API Gateway'.

## Testing

We can run the 'API Gateway', 'Web Client Backend' and 'Mobile Client Backend' that we developed above, in our local 
environment. To complete the design diagram illustrated above, we have to run the 
['OAuth Authorization Server'](https://hub.docker.com/repository/docker/ldclakmal/wso2is-sts) first.
Open the terminal and execute the following command. This will take few seconds to start and run.
```shell
$ docker run -d -p 9443:9443 ldclakmal/wso2is-sts:latest
```

Now, navigate to [`examples/order-management-service/api_gateway`](./api_gateway) directory and execute the following command.
```shell
$ bal run
```

The successful execution of the service should show us the following output.
```shell
Compiling source
        oauth2/api_gateway:1.0.0

Running executable
```

Now, navigate to [`examples/order-management-service/app_backend`](./app_backend) directory and execute the same command.
The successful execution of the service should show us the following output.
```shell
Compiling source
        oauth2/app_backend:1.0.0

Running executable
```

Now, we can test authentication and authorization checks being enforced on different actions by sending HTTP requests. 
For example, we have used the CURL commands to test each scenario as follows.

### Scenario 1 - Web App

```shell
curl -k -v "https://localhost:8080/order/web?orderId=100500"
```

Output:
```shell
< HTTP/1.1 200 OK
< content-type: application/json
< content-length: 163
< server: ballerina
< date: Fri, 3 Sep 2021 10:35:37 +0530

{"id":"100500", "name":"Sample order", "items":[{"category":"electronics", "code":"SOWH1000XM4", "qty":2}, {"category":"books", "code":"978-1617295959", "qty":1}]}
```

### Scenario 2 - Mobile App

Here, we need to export our ID Token, that the mobile client received for the OpenID Connect (OIDC) response from the 
'OAuth Authorization Server'. 
Refer to [WSO2 Identity Server Documentation - OpenID Connect](https://is.docs.wso2.com/en/latest/learn/openid-connect/) 
for more information.
```shell
export ID_TOKEN="eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTVdJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJhZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NDQ0NzI2MjksICJuYmYiOjE2MjkxMTI2MjksICJpYXQiOjE2MjkxMTI2Mjl9.Qbi5kElPZlyViUUuYW9Ik4nXSeTIroacEDs4BoI0rAGAOBXfyWLW4Yxm6hAlb4GXtkPZ4YMO8c0mUgdXgvPVFqFYJuINNPu6Y_nExahAVD0VxCYRE59lEjRv7t_gqn5OxSu_jTGcgcHH8_j-tvL_-AHaqgflr5UljbTPtnQyXtLaPNeu3r7FoWs-LrewMPIm1aw5qc2gI2iYwI1jfIdpNlEjU6r_Mg6ou2D2AGqJa0QYN1FMqi4YJt2jHr60tQMQIWJ7zhKU4ShZESxYOVKK_cBOeL6K-A07pNEZYaSxtCU3609MIZ8EOUJuQUJb7zHHxG4QziHM8eBwFo26yovBFw";

curl -k -v "https://localhost:8080/order/mobile?orderId=100500&idToken=$ID_TOKEN"
```

Output:
```shell
< HTTP/1.1 200 OK
< content-type: application/json
< content-length: 163
< server: ballerina
< date: Fri, 3 Sep 2021 10:35:37 +0530

{"id":"100500", "name":"Sample order", "items":[{"category":"electronics", "code":"SOWH1000XM4", "qty":2}, {"category":"books", "code":"978-1617295959", "qty":1}]}
```

## Deployment

Once we are done with the development, we can deploy the service using any of the methods that are listed below.

### Deploying Locally

As the first step, we have to run the 'OAuth Authorization Server' first. Open the terminal and execute the following 
command. This will take few seconds to start and run.
```shell
$ docker run -d -p 9443:9443 ldclakmal/wso2is-sts:latest
```

Now, we can build Ballerina executable files (.jar) of the components that we developed above. Open the terminal and 
navigate to [`examples/order-management-service/api_gateway`](./api_gateway), and
[`examples/order-management-service/app_backend`](./app_backend) directories, and execute the following command for 
each of them.
```shell
$ bal build
```

The successful execution of the above command should show us the following outputs in order.
```shell
Compiling source
        oauth2/api_gateway:1.0.0

Generating executable
        target/bin/api_gateway.jar
```

```shell
Compiling source
        oauth2/app_backend:1.0.0

Generating executable
        target/bin/app_backend.jar
```

Once the `*.jar` files are created inside the `target/bin` directories, we can run the components with the following 
commands in order.
```shell
$ bal run target/bin/api_gateway.jar
$ bal run target/bin/app_backend.jar
```

### Deploying Code to Cloud

Ballerina code to cloud supports generating the deployment artifacts of the Docker and Kubernetes.
Refer to [Code to Cloud](https://ballerina.io/learn/user-guide/deployment/code-to-cloud/) guide for more information.

## Observability

HTTP/HTTPS based Ballerina services and any client connectors are observable by default.
[Observing Ballerina Code](https://ballerina.io/learn/user-guide/observability/observing-ballerina-code/) guide provides 
information on enabling Ballerina service observability with some of its supported systems.
