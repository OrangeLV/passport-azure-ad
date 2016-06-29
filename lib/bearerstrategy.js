/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the 'Software'), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
'use strict';

/* eslint no-underscore-dangle: 0 */

const passport = require('passport');
const util = require('util');
const jwt = require('jsonwebtoken');
const async = require('async');
const Metadata = require('./metadata').Metadata;
const Log = require('./logging').getLogger;
const jws = require('jws');

const log = new Log('AzureAD: Bearer Strategy');

/**
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 * or
 *     function(req, token, done) { ... }
 *
 * The latter enables you to use the request object. In order to use this
 * signature, the passReqToCallback value in options (see the Options instructions
 * below) must be set true, so the strategy knows you want to pass the request
 * to the `verify` callback function.
 *
 * `token` is the verified and decoded bearer token provided as a credential.
 * The verify callback is responsible for finding the user who posesses the
 * token, and invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 * 
 *
 * Options:
 *
 *   - `realm`    authentication realm, defaults to 'Users'
 *   - `scope`    list of scope values indicating the required scope of the
 *                access token for accessing the requested resource
 *   - `audience` if you want to check JWT audience (aud), provide a value here
 *   - `issuer`   if you want to check JWT issuer (iss), provide a value here
 *   - `loggingLevel`
 *                'info', 'warn' or 'error'. Error always goes to stderr in Unix
 *   - `validateIssuer`
 *                'true' or 'false'. Strategy cannot handle uses from multiple 
 *                tenants if set to 'true'
 *   - `passReqToCallback`
 *                'true' or 'false'. Must set to 'true' if you want to pass the
 *                'req' object to your verify callback
 *   - `clientID` your client id in AAD
 *   - `identityMetadata`
 *                If you have users from multiple tenants (in the case of B2C), use
 *                'https://login.microsoftonline.com/common/.well-known/openid-configuration'
 *                Otherwise, replace 'common' with your tenant name (something 
 *                like *.onmicrosoft.com) or your tenant id
 *   - `policyName`
 *                Policy name (B2C only)
 *   - `tenantName`
 *                Tenant name (B2C only, specify the tenant from multiple tenants)
 *
 *
 * Examples:
 *
 *     passport.use(new BearerStrategy(
 *       options,
 *       function(token, done) {
 *         User.findById(token.sub, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, token);
 *         });
 *       }
 *     ));
 *
 * The name of this strategy is 'oauth-bearer', so use this name as the first 
 * parameter of the authenticate function. Moreover, we don't need session 
 * support for request containing bearer tokens, so the session option can be
 * set to false.
 * 
 *     app.get('/protected_resource', 
 *       passport.authenticate('oauth-bearer', {session: false}), 
 *       function(req, res) { 
 *         ... 
 *       });
 *
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens]
 * (http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 * For further details on JSON Web Token, refert to [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token)
 *
 * @param {object} options - The Options.
 * @param {Function} verify - The verify callback.
 * @constructor
 */

function Strategy(options, verifyFn) {
  passport.Strategy.call(this);
  this.name = 'oauth-bearer'; // Me, a name I call myself.

  this._verify = (typeof options === 'function') ? options : verifyFn;
  this._options = (typeof options === 'function') ? {} : options;

  options = this._options;

  // Passport requires a verify function
  if (typeof this._verify !== 'function') {
    throw new TypeError('BearerStrategy requires a verify callback.');
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  // warn about validating the issuer
  if (!options.validateIssuer) {
    log.warn(`We are not validating the issuer.
      This is fine if you are expecting multiple organizations to connect to your app.
      Otherwise you should validate the issuer.`);
  }

  // if you want to check JWT audience (aud), provide a value here
  if (options.audience) {
    log.info('Audience provided to Strategy was: ', options.audience);
  }

  this._realm = options.realm || 'Users';
  if (options.scope)
    this._scope = (Array.isArray(options.scope) ? toptions.scope : [options.scope]);
  this._passReqToCallback = options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.jwtVerify = function jwtVerifyFunc(req, token, done) {
  const self = this;

  const decoded = jws.decode(token);
  let PEMkey = null;

  if (decoded == null) {
    done(null, false, 'Invalid JWT token.');
  }

  log.info('token decoded:  ', decoded);

  // We have two different types of token signatures we have to validate here. One provides x5t and the other a kid.
  // We need to call the right one.

  if (decoded.header.x5t) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.x5t);
  } else if (decoded.header.kid) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.kid);
  } else {
    throw new TypeError('We did not reveive a token we know how to validate');
  }

  jwt.verify(token, PEMkey, options, (err, verifiedToken) => {
    if (err) {
      if (err instanceof jwt.TokenExpiredError) {
        log.warn('Access token expired');
        return done(null, false, 'The access token expired');
      }
      if (err instanceof jwt.JsonWebTokenError) {
        log.warn('An error was received validating the token', err.message);
        return done(null, false, util.format('Invalid token (%s)', err.message));
      }
      return done(err, false);
    }
    log.info(verifiedToken, 'was token going out of verification');
    if (self._options.passReqToCallback) {
      log.info('We did pass Req back to Callback');
      return self._verify(req, verifiedToken, done);
    }
    log.info('We did not pass Req back to Callback');
    return self._verify(verifiedToken, done);
  });
}

Strategy.prototype.authenticate = function authenticateStrategy(req) {
  const self = this;

  async.waterfall([
    // compute metadata url
    (next) => {
      if (self._options.policyName) {
        log.info('B2C: We have been instructed that this is a B2C tenant. We will configure as required.');
        if (!self._options.tenantName) {
          return next(new TypeError('BearerStrategy requires you pass the tenant name if using a B2C tenant.'));
        } else {
          // We are replacing the common endpoint with the concrete metadata of a B2C tenant.
          self._options.identityMetadata = self._options.identityMetadata
            .replace('common', self._options.tenantName)
            .concat(`?p=${self._options.policyName}`);
        }
      }

      if (self._options.identityMetadata) {
        log.info('Metadata url provided to Strategy was: ', self._options.identityMetadata);
        self.metadata = new Metadata(self._options.identityMetadata, 'oidc', self._options);
      }

      if (!self._options.certificate && !self._options.identityMetadata) {
        log.warn('No options was presented to Strategy as required.');
        return next(new TypeError(`BearerStrategy requires either a PEM encoded public key\ 
          or a metadata location that contains cert data for RSA and ECDSA callback.`));
      }

      return next();
    },

    (next) => {
      self.metadata.fetch((fetchMetadataError) => {
        if (fetchMetadataError) {
          return next(new Error(`Unable to fetch metadata: ${fetchMetadataError}`));
        }
        if (self._options.validateIssuer) {
          self._options.issuer = self.metadata.oidc.issuer;
        }
        self._options.algorithms = self.metadata.oidc.algorithms;
      });
      return next();
    },

    (next) => {
      var token;

      if (req.headers && req.headers.authorization) {
        var auth_components = req.headers.authorization.split(' ');
        if (auth_components.length == 2) {
          if (/^Bearer$/.test(auth_components[0]))
            token = auth_components[1];
        } else {
          return self.fail(400);
        }
      }

      if (req.body && req.body.access_token) {
        if (token)
          return self.fail(400);
        token = req.body.access_token;
      }

      if (req.query && req.query.access_token) {
        if (token)
          return self.fail(400);
        token = req.query.access_token;
      }

      if (!token)
        return self.fail(self._challenge());

      function verified(err, user, info) {
        if (err)
          return self.error(err);
        if (!user) {
          if (typeof info == 'string')
            info = {message: info};
          info = info || {};
          return self.fail(self._challenge('invalid_token', info.message));
        }
      }

      return self.jwtVerify(req, token, verified);
    }],

    (waterfallError) => { // This function gets called after the three tasks have called their 'task callbacks'
      if (waterfallError) {
        return self.error(waterfallError);
      }
      return true;
    }
  );
};

/* 
 * build authentication challenge
 */
Strategy.prototype._challenge = function challengeFunc(code, desc, uri) {
  var challenge = 'Bearer realm="' + this._realm +'"';
  if (this._scope)
    challenge += ', scope="' + this._scope.join(' ') + '"';
  if (code)
    challenge += ', error=' + code + '"';
  if (desc && desc.length)
    challenge += ', error_description="' +  desc + '"';
  if (uri && uri.length)
    challenge += ', error_uri="' + uri + '"';
  return challenge;
}

module.exports = Strategy;
