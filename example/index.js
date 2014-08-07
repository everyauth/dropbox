var everyauth = require('everyauth');
everyauth.debug = true;
var conf = require('./conf');

var usersById = {};
var nextUserId = 0;
function addUser (source, sourceUser) {
  var user;
  if (arguments.length === 1) { // password-based
    user = sourceUser = source;
    user.id = ++nextUserId;
    return usersById[nextUserId] = user;
  } else { // non-password-based
    user = usersById[++nextUserId] = {id: nextUserId};
    user[source] = sourceUser;
  }
  return user;
}

everyauth.everymodule
.findUserById( function (id, callback) {
  callback(null, usersById[id]);
});

everyauth.use(require("everyauth-dropbox"));
var usersByDropboxId = {};
everyauth.dropbox
.appId(conf.dropbox.consumerKey)
.appSecret(conf.dropbox.consumerSecret)
.callbackPath("/auth/dropbox/callback")
.findOrCreateUser( function (sess, accessToken, accessSecret, dropboxUserMetadata) {
  return usersByDropboxId[dropboxUserMetadata.uid] ||
    (usersByDropboxId[dropboxUserMetadata.uid] = addUser('dropbox', dropboxUserMetadata));
});

var express = require('express');
var app = express();
app.use(express.static(__dirname + '/public'))
  .use(require('serve-favicon')(__dirname + '/public/favicon.ico'))
  .use(require('body-parser').urlencoded({extended: true}))
  .use(require('body-parser').json())
  .use(require('cookie-parser')('htuayreve'))
  .use(require('express-session')({
    secret: 'htuayreve'
  , resave: true
  , saveUninitialized: true
  }))
  .use(everyauth.loadUser())
  .use(everyauth.addRequestLocals('user'));

app.set('view engine', 'jade');
var everyauthRoot = __dirname + '/..';
app.set('views', everyauthRoot + '/example/views');

app.get('/', function (req, res) {
  res.render('home');
});

app.get('/auth/dropbox'
  , everyauth.dropbox.middleware('entryPath')
  , function (err, req, res, next) {
      console.log(err.stack);
      res.render('auth-fail.jade', {
        error: err.toString()
      });
    });

app.get('/auth/dropbox/callback'
  , everyauth.dropbox.middleware('callbackPath')
  , function (req, res, next) {
      res.redirect("/");
    }
  , function (err, req, res, next) {
      console.log(err.stack);
      res.render('auth-fail.jade', {
        error: err.toString()
      });
    });

app.get("/logout", function (req, res, next) {
  everyauth.logout(req);
  res.redirect("/");
});

app.listen(3000);

console.log('Go to http://localhost:3000');

module.exports = app;
