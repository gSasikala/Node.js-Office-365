'use strict';
//added line 2-4
require('dotenv').config();
var graph = require('./graph');
var session = require('express-session');
var flash = require('connect-flash');

var debug = require('debug');
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

//added lines 16-66
var passport = require('passport');
var OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

// Configure passport

// In-memory storage of logged-in users
// For demo purposes only, production apps should store
// this in a reliable storage
var users = {};

// Passport calls serializeUser and deserializeUser to
// manage users
passport.serializeUser(function (user, done) {
    // Use the OID property of the user as a key
    users[user.profile.oid] = user;
    done(null, user.profile.oid);
});

passport.deserializeUser(function (id, done) {
    done(null, users[id]);
});
// Configure simple-oauth2
const oauth2 = require('simple-oauth2').create({
    client: {
        id: process.env.OAUTH_APP_ID,
        secret: process.env.OAUTH_APP_PASSWORD
    },
    auth: {
        tokenHost: process.env.OAUTH_AUTHORITY,
        authorizePath: process.env.OAUTH_AUTHORIZE_ENDPOINT,
        tokenPath: process.env.OAUTH_TOKEN_ENDPOINT
    }
});
// Callback function called once the sign-in is complete
// and an access token has been obtained
async function signInComplete(iss, sub, profile, accessToken, refreshToken, params, done) {
    if (!profile.oid) {
        return done(new Error("No OID found in user profile."), null);
    }

    try {
        const user = await graph.getUserDetails(accessToken);

        if (user) {
            // Add properties to profile
            profile['email'] = user.mail ? user.mail : user.userPrincipalName;
        }
    } catch (err) {
        done(err, null);
    }

    // Create a simple-oauth2 token from raw tokens
    let oauthToken = oauth2.accessToken.create(params);

    // Save the profile and tokens in user storage
    users[profile.oid] = { profile, oauthToken };
    return done(null, users[profile.oid]);
}
// Configure OIDC strategy
passport.use(new OIDCStrategy(
    {
        identityMetadata: `${process.env.OAUTH_AUTHORITY}${process.env.OAUTH_ID_METADATA}`,
        clientID: process.env.OAUTH_APP_ID,
        responseType: 'code id_token',
        responseMode: 'form_post',
        redirectUrl: process.env.OAUTH_REDIRECT_URI,
        allowHttpForRedirectUrl: true,
        clientSecret: process.env.OAUTH_APP_PASSWORD,
        validateIssuer: false,
        passReqToCallback: false,
        scope: process.env.OAUTH_SCOPES.split(' ')
    },
    signInComplete
));
var routes = require('./routes/index');
var users = require('./routes/users');
var authRouter = require('./routes/auth');
var aboutRouter = require('./routes/about');

var app = express();
//added lines 19-46
// Session middleware
// NOTE: Uses default in-memory session store, which is not
// suitable for production
app.use(session({
    secret: 'your_secret_value_here',
    resave: false,
    saveUninitialized: false,
    unset: 'destroy'
}));

// Flash middleware
app.use(flash());

// Set up local vars for template layout
app.use(function (req, res, next) {
    // Read any flashed errors and save
    // in the response locals
    res.locals.error = req.flash('error_msg');

    // Check for simple error string and
    // convert to layout's expected format
    var errs = req.flash('error');
    for (var i in errs) {
        res.locals.error.push({ message: 'An error occurred', debug: errs[i] });
    }

    next();
});
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//added lines 112-115
// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

app.use(function (req, res, next) {
    // Set the authenticated user in the
    // template locals
    if (req.user) {
        res.locals.user = req.user.profile;
    }
    next();
});

app.use('/', routes);
app.use('/users', users);
app.use('/auth', authRouter);
app.use('/about', aboutRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function (err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

app.set('port', process.env.PORT || 3000);

var server = app.listen(app.get('port'), function () {
    debug('Express server listening on port ' + server.address().port);
});
