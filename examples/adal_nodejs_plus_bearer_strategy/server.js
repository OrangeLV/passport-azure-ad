var options = {
  identityMetadata : 'https://login.microsoftonline.com/sijun.onmicrosoft.com/.well-known/openid-configuration',
  clientID : 'c233db9a-58e8-4055-a432-81914adbfc54',
  clientSecret : 'FDKC4+58qyg/X1+RYHmHtGKM7aQY6I2xHb5qAvkmzuQ='
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

app.get('/protected', passport.authenticate('oauth-bearer', {session : false}), 
  function(req, res) {
    res.send("owner is: " + owner);
  });