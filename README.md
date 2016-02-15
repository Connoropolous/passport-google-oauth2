# passport-ctauth

[Passport](http://passportjs.org/) strategy for authenticating with [CTAuth](https://ctauth.com/)
using the OAuth 2.0 API.

This module lets you authenticate using CTAuth in your Node.js applications.
By plugging into Passport, CTAuth authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-ctauth

## Usage

#### Create an Application

Before using `passport-ctauth`, you must register an application with CTAuth.
Your application will be issued a client ID and client secret, which need to be
provided to the strategy.  You will also need to configure a redirect URI which
matches the route in your application.

#### Configure Strategy

    var CTAuthStrategy = require('passport-ctauth').Strategy;

    passport.use(new CTAuthStrategy({
        clientID: CTAUTH_CLIENT_ID,
        clientSecret: CTAUTH_CLIENT_SECRET,
        callbackURL: "http://www.example.com/auth/ctauth/callback"
      },
      function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ ctauthId: profile.id }, function (err, user) {
          return cb(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'ctauth'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/ctauth',
      passport.authenticate('ctauth', { scope: ['profile'] }));

    app.get('/auth/ctauth/callback', 
      passport.authenticate('ctauth', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

#### Tests

The test suite is located in the `test/` directory.  All new features are
expected to have corresponding test cases.  Ensure that the complete test suite
passes by executing:

```bash
$ make test
```

#### Coverage

The test suite covers 100% of the code base.  All new feature development is
expected to maintain that level.  Coverage reports can be viewed by executing:

```bash
$ make test-cov
$ make view-cov
```

## License
credit to Jared Hanson for his work as this is a fork of https://github.com/jaredhanson/passport-google-oauth20

[The MIT License](http://opensource.org/licenses/MIT)
