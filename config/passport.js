// config/passport.js

// load all the things we need
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var OpenIDGoogleStrategy = require('passport-openidconnect').Strategy;
var OpenIDHerokuStrategy = require('passport-openidconnect').Strategy;
var OpenIDLocalOPENiStrategy = require('passport-openidconnect').Strategy;
var OpenIDOPENiStrategy = require('passport-openidconnect').Strategy;

// load up the user model
var User = require('../app/models/user');

// load the auth variables
var configAuth = require('./auth');

// expose this function to our app using module.exports
module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
        },
        function(req, email, password, done) {

            // asynchronous
            process.nextTick(function() {
                // check if the user is already logged ina
                if (!req.user) {
                    User.findOne({
                        'local.email': email
                    }, function(err, user) {
                        // if there are any errors, return the error
                        if (err)
                            return done(err);

                        // check to see if theres already a user with that email
                        if (user) {
                            return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                        } else {

                            // create the user
                            var newUser = new User();

                            newUser.local.email = email;
                            newUser.local.password = newUser.generateHash(password);

                            newUser.save(function(err) {
                                if (err)
                                    throw err;

                                return done(null, newUser);
                            });
                        }

                    });
                } else {

                    var user = req.user;
                    user.local.email = email;
                    user.local.password = user.generateHash(password);
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });

                }

            });

        }));

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
        },
        function(req, email, password, done) {

            // asynchronous
            process.nextTick(function() {
                User.findOne({
                    'local.email': email
                }, function(err, user) {
                    // if there are any errors, return the error
                    if (err)
                        return done(err);

                    // if no user is found, return the message
                    if (!user)
                        return done(null, false, req.flash('loginMessage', 'No user found.'));

                    if (!user.validPassword(password))
                        return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));

                    // all is well, return user
                    else
                        return done(null, user);
                });
            });

        }));

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    passport.use(new FacebookStrategy({

            // pull in our app id and secret from our auth.js file
            clientID: configAuth.facebookAuth.clientID,
            clientSecret: configAuth.facebookAuth.clientSecret,
            callbackURL: configAuth.facebookAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },

        // facebook will send back the token and profile
        function(req, token, refreshToken, profile, done) {

            // asynchronous
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    // find the user in the database based on their facebook id
                    User.findOne({
                        'facebook.id': profile.id
                    }, function(err, user) {

                        // if there is an error, stop everything and return that
                        // ie an error connecting to the database
                        if (err)
                            return done(err);

                        // if the user is found, then log them in
                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.facebook.token) {
                                user.facebook.token = token;
                                user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                                user.facebook.email = profile.emails[0].value;

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            return done(null, user); // user found, return that user
                        } else {
                            // if there is no user found with that facebook id, create them
                            var newUser = new User();

                            // set all of the facebook information in our user model
                            newUser.facebook.id = profile.id; // set the users facebook id                   
                            newUser.facebook.token = token; // we will save the token that facebook provides to the user                    
                            newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
                            newUser.facebook.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first

                            // save our user to the database
                            newUser.save(function(err) {
                                if (err)
                                    throw err;

                                // if successful, return the new user
                                return done(null, newUser);
                            });
                        }

                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.facebook.id = profile.id;
                    user.facebook.token = token;
                    user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                    user.facebook.email = profile.emails[0].value;

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });

        }));

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================
    passport.use(new TwitterStrategy({

            consumerKey: configAuth.twitterAuth.consumerKey,
            consumerSecret: configAuth.twitterAuth.consumerSecret,
            callbackURL: configAuth.twitterAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },
        function(req, token, tokenSecret, profile, done) {

            // make the code asynchronous
            // User.findOne won't fire until we have all our data back from Twitter
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    User.findOne({
                        'twitter.id': profile.id
                    }, function(err, user) {

                        // if there is an error, stop everything and return that
                        // ie an error connecting to the database
                        if (err)
                            return done(err);

                        // if the user is found then log them in
                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.twitter.token) {
                                user.twitter.token = token;
                                user.twitter.username = profile.username;
                                user.twitter.displayName = profile.displayName;

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            return done(null, user); // user found, return that user
                        } else {
                            // if there is no user, create them
                            var newUser = new User();

                            // set all of the user data that we need
                            newUser.twitter.id = profile.id;
                            newUser.twitter.token = token;
                            newUser.twitter.username = profile.username;
                            newUser.twitter.displayName = profile.displayName;

                            // save our user into the database
                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.twitter.id = profile.id;
                    user.twitter.token = token;
                    user.twitter.username = profile.username;
                    user.twitter.displayName = profile.displayName;

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }

            });

        }));

    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    passport.use(new GoogleStrategy({

            clientID: configAuth.googleAuth.clientID,
            clientSecret: configAuth.googleAuth.clientSecret,
            callbackURL: configAuth.googleAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },
        function(req, token, refreshToken, profile, done) {

            // make the code asynchronous
            // User.findOne won't fire until we have all our data back from Google
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    // try to find the user based on their google id
                    User.findOne({
                        'google.id': profile.id
                    }, function(err, user) {
                        if (err)
                            return done(err);

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.google.token) {
                                user.google.token = token;
                                user.google.name = profile.displayName;
                                user.google.email = profile.emails[0].value; // pull the first email

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            // if a user is found, log them in
                            return done(null, user);
                        } else {
                            // if the user isnt in our database, create a new user
                            var newUser = new User();

                            // set all of the relevant information
                            newUser.google.id = profile.id;
                            newUser.google.token = token;
                            newUser.google.name = profile.displayName;
                            newUser.google.email = profile.emails[0].value; // pull the first email

                            // save the user
                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.google.id = profile.id;
                    user.google.token = token;
                    user.google.name = profile.displayName;
                    user.google.email = profile.emails[0].value; // pull the first email

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });

        }));

    // =========================================================================
    // OPENID GOOGLE ==========================================================
    // =========================================================================
    passport.use('openidgoogle', new OpenIDGoogleStrategy({

            authorizationURL: 'https://accounts.google.com/o/oauth2/auth',
            tokenURL: 'https://accounts.google.com/o/oauth2/token',
            userInfoURL: 'https://www.googleapis.com/plus/v1/people/me',
            clientID: configAuth.openidgoogleAuth.clientID,
            clientSecret: configAuth.openidgoogleAuth.clientSecret,
            callbackURL: configAuth.openidgoogleAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },
        function(req, token, refreshToken, profile, done) {

            // make the code asynchronous
            // User.findOne won't fire until we have all our data back from Google
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    // try to find the user based on their google id
                    User.findOne({
                        'openidgoogle.id': profile.id
                    }, function(err, user) {
                        if (err)
                            return done(err);

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.openidgoogle.token) {
                                user.openidgoogle.token = token;
                                user.openidgoogle.name = profile.displayName;
                                user.openidgoogle.email = profile.emails[0].value; // pull the first email

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            // if a user is found, log them in
                            return done(null, user);
                        } else {
                            // if the user isnt in our database, create a new user
                            var newUser = new User();

                            // set all of the relevant information
                            newUser.openidgoogle.id = profile.id;
                            newUser.openidgoogle.token = token;
                            newUser.openidgoogle.name = profile.displayName;
                            newUser.openidgoogle.email = profile.emails[0].value; // pull the first email

                            // save the user
                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.openidgoogle.id = profile.id;
                    user.openidgoogle.token = token;
                    user.openidgoogle.name = profile.displayName;
                    user.openidgoogle.email = profile.emails[0].value; // pull the first email

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });

        }));

    // =========================================================================
    // OPENID HEROKU ==========================================================
    // =========================================================================
    passport.use('openidheroku', new OpenIDHerokuStrategy({

            authorizationURL: 'https://connect-op.heroku.com/authorizations/new',
            tokenURL: 'https://connect-op.heroku.com/access_tokens',
            userInfoURL: 'https://connect-op.heroku.com/user_info',
            clientID: configAuth.openidherokuAuth.clientID,
            clientSecret: configAuth.openidherokuAuth.clientSecret,
            callbackURL: configAuth.openidherokuAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },
        function(req, token, refreshToken, profile, done) {

            // make the code asynchronous
            // User.findOne won't fire until we have all our data back from Google
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    // try to find the user based on their google id
                    User.findOne({
                        'openidheroku.id': profile.id
                    }, function(err, user) {
                        if (err)
                            return done(err);

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.openidheroku.token) {
                                user.openidheroku.token = token;
                                user.openidheroku.name = profile.displayName;
                                user.openidheroku.email = profile.emails; // pull the first email

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            // if a user is found, log them in
                            return done(null, user);
                        } else {
                            // if the user isnt in our database, create a new user
                            var newUser = new User();

                            // set all of the relevant information
                            newUser.openidheroku.id = profile.id;
                            newUser.openidheroku.token = token;
                            newUser.openidheroku.name = profile.displayName;
                            newUser.openidheroku.email = profile.emails; // pull the first email

                            // save the user
                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.openidheroku.id = profile.id;
                    user.openidheroku.token = token;
                    user.openidheroku.name = profile.displayName;
                    user.openidheroku.email = profile.emails; // pull the first email

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });

        }));

    // =========================================================================
    // LOCAL OPENi =============================================================
    // =========================================================================
    passport.use('openidlocalopeni', new OpenIDLocalOPENiStrategy({

            authorizationURL: 'http://localhost:3000/authorizations/new',
            tokenURL: 'http://localhost:3000/access_tokens',
            userInfoURL: 'http://localhost:3000/user_info',
            clientID: configAuth.openidLocalOPENiAuth.clientID,
            clientSecret: configAuth.openidLocalOPENiAuth.clientSecret,
            callbackURL: configAuth.openidLocalOPENiAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },
        function(req, token, refreshToken, profile, done) {

            // make the code asynchronous
            // User.findOne won't fire until we have all our data back from Google
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    // try to find the user based on their google id
                    User.findOne({
                        'localopeni.id': profile.id
                    }, function(err, user) {
                        if (err)
                            return done(err);

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.openidlocalopeni.token) {
                                user.openidlocalopeni.token = token;
                                user.openidlocalopeni.name = profile.displayName;
                                user.openidlocalopeni.email = profile.emails; // pull the first email

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            // if a user is found, log them in
                            return done(null, user);
                        } else {
                            // if the user isnt in our database, create a new user
                            var newUser = new User();

                            // set all of the relevant information
                            newUser.openidlocalopeni.id = profile.id;
                            newUser.openidlocalopeni.token = token;
                            newUser.openidlocalopeni.name = profile.displayName;
                            newUser.openidlocalopeni.email = profile.emails; // pull the first email

                            // save the user
                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.openidlocalopeni.id = profile.id;
                    user.openidlocalopeni.token = token;
                    user.openidlocalopeni.name = profile.displayName;
                    user.openidlocalopeni.email = profile.emails; // pull the first email

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });

        }));

    // =========================================================================
    // OPENi ===================================================================
    // =========================================================================
    passport.use('openidopeni', new OpenIDOPENiStrategy({

            authorizationURL: 'http://localhost:3000/authorizations/new',
            tokenURL: 'http://localhost:3000/access_tokens',
            userInfoURL: 'http://localhost:3000/user_info',
            clientID: configAuth.openidOPENiAuth.clientID,
            clientSecret: configAuth.openidOPENiAuth.clientSecret,
            callbackURL: configAuth.openidOPENiAuth.callbackURL,
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

        },
        function(req, token, refreshToken, profile, done) {

            // make the code asynchronous
            // User.findOne won't fire until we have all our data back from Google
            process.nextTick(function() {

                // check if the user is already logged in
                if (!req.user) {

                    // try to find the user based on their google id
                    User.findOne({
                        'openi.id': profile.id
                    }, function(err, user) {
                        if (err)
                            return done(err);

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information
                            if (!user.openidopeni.token) {
                                user.openidopeni.token = token;
                                user.openidopeni.name = profile.displayName;
                                user.openidopeni.email = profile.emails; // pull the first email

                                user.save(function(err) {
                                    if (err)
                                        throw err;
                                    return done(null, user);
                                });
                            }

                            // if a user is found, log them in
                            return done(null, user);
                        } else {
                            // if the user isnt in our database, create a new user
                            var newUser = new User();

                            // set all of the relevant information
                            newUser.openidopeni.id = profile.id;
                            newUser.openidopeni.token = token;
                            newUser.openidopeni.name = profile.displayName;
                            newUser.openidopeni.email = profile.emails; // pull the first email

                            // save the user
                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user; // pull the user out of the session

                    // update the current users facebook credentials
                    user.openidopeni.id = profile.id;
                    user.openidopeni.token = token;
                    user.openidopeni.name = profile.displayName;
                    user.openidopeni.email = profile.emails; // pull the first email

                    // save the user
                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });

        }));
};