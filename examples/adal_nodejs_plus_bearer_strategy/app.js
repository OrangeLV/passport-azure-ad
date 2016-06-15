/*
 * @copyright
 * Copyright © Microsoft Open Technologies, Inc.
 *
 * All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: *www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 */
'use strict';

var express = require('express');
var logger = require('connect-logger');
var cookieParser = require('cookie-parser');
var session = require('cookie-session');
var fs = require('fs');
var crypto = require('crypto');

var passport = require('passport');
var BearerStrategy = require('../../lib/index').BearerStrategy;

var AuthenticationContext = require('adal-node').AuthenticationContext;

var app = express();
app.use(logger());
app.use(cookieParser('a deep secret'));
app.use(session({secret: '1234567890QWERTY'}));


var sampleParameters = {
    tenant : 'sijun.onmicrosoft.com',
    clientId : 'c233db9a-58e8-4055-a432-81914adbfc54',
    clientSecret : 'FDKC4+58qyg/X1+RYHmHtGKM7aQY6I2xHb5qAvkmzuQ=',
    redirectUri : 'http://localhost:3000/getAToken',
    resource : '81bfd647-8cea-425e-ad4d-e8ab5c43004a'
};

var options = {
  identityMetadata : 'https://login.microsoftonline.com/sijun.onmicrosoft.com/.well-known/openid-configuration',
  clientID : 'c233db9a-58e8-4055-a432-81914adbfc54',
  clientSecret : 'FDKC4+58qyg/X1+RYHmHtGKM7aQY6I2xHb5qAvkmzuQ='
}

var authorityUrl = 'https://login.microsoftonline.com/' + sampleParameters.tenant;

//var templateAuthzUrl = authorityUrl + '/oauth2/authorize?response_type=code&client_id=<client_id>&redirect_uri=<redirect_uri>&state=<state>&resource=<resource>';
var templateAuthzUrl = authorityUrl + '/oauth2/authorize?response_type=code&client_id=<client_id>&redirect_uri=<redirect_uri>&state=<state>';

function createAuthorizationUrl(state) {
  var authorizationUrl = templateAuthzUrl.replace('<client_id>', sampleParameters.clientId);
  authorizationUrl = authorizationUrl.replace('<redirect_uri>',sampleParameters.redirectUri);
  authorizationUrl = authorizationUrl.replace('<state>', state);
  //authorizationUrl = authorizationUrl.replace('<resource>', sampleParameters.resource);
  return authorizationUrl;
}


/*
 *      Passport setup
 */
var owner = null;
var users = [];

var findByToken =  function(token) {
  for (var i = 0, len = users.length; i < len; i++) {
    if (users[i] == token.sub)
      return users[i];
  }
  return null;
}

passport.use(new BearerStrategy(options,
      function(token, done) {
          console.log("get token: " + token);
          var user = findByToken(token);
          if (!user)
            users.push(user);
          owner = user;
          done(null, user);
     }
));



/*
 *      Routing
 */

app.get('/protected', passport.authenticate('oauth-bearer', {session : false}), 
  function(req, res) {
    res.send("owner is: " + owner);
  });

app.get('/', function(req, res) {
  res.redirect('login');
});


app.get('/login', function(req, res) {
  console.log(req.cookies);

  res.cookie('acookie', 'this is a cookie');

  res.send('\
<head>\
  <title>FooBar</title>\
</head>\
<body>\
  <a href="./auth">Login</a>\
</body>\
    ');
});

// Clients get redirected here in order to create an OAuth authorize url and redirect them to AAD.
// There they will authenticate and give their consent to allow this app access to
// some resource they own.
app.get('/auth', function(req, res) {
  crypto.randomBytes(48, function(ex, buf) {
    var token = buf.toString('base64').replace(/\//g,'_').replace(/\+/g,'-');

    res.cookie('authstate', token);
    var authorizationUrl = createAuthorizationUrl(token);

    res.redirect(authorizationUrl);
  });
});

// After consent is granted AAD redirects here.  The ADAL library is invoked via the
// AuthenticationContext and retrieves an access token that can be used to access the
// user owned resource.
app.get('/getAToken', function(req, res) {
  if (req.cookies.authstate !== req.query.state) {
    res.send('error: state does not match');
  }
  var authenticationContext = new AuthenticationContext(authorityUrl);
  authenticationContext.acquireTokenWithAuthorizationCode(req.query.code, sampleParameters.redirectUri, sampleParameters.resource, sampleParameters.clientId, sampleParameters.clientSecret, function(err, response) {
    var message = '';
    if (err) {
      message = 'error: ' + err.message + '\n';
    }
    message += 'response: ' + JSON.stringify(response);

    if (err) {
      res.send(message);
      return;
    }

    // Later, if the access token is expired it can be refreshed.
    authenticationContext.acquireTokenWithRefreshToken(response.refreshToken, sampleParameters.clientId, sampleParameters.clientSecret, sampleParameters.resource, function(refreshErr, refreshResponse) {
      if (refreshErr) {
        message += 'refreshError: ' + refreshErr.message + '\n';
      }
      message += 'refreshResponse: ' + JSON.stringify(refreshResponse);

      res.send(message); 
    }); 
  });
});

app.listen(3000);
console.log('listening on 3000');

