var util = require("util");
var url = require("url");
var crypto = require("crypto");
var request = require("request");

module.exports = function (everyauth) {
  if (! everyauth.oauth2) {
    everyauth.oauth2 = require("everyauth-oauth2")(everyauth);
  }
  everyauth.dropbox =
  everyauth.oauth2.submodule("dropbox")

  .apiHost('https://api.dropbox.com/1')

  .oauthHost('https://www.dropbox.com/1/oauth2')
  .authPath("/authorize")
  .authQueryParam('response_type', 'code')
  .authQueryParam('state', function (req, res) {
    var csrf = generateCsrfToken();
    res.cookie("dropbox.csrf", csrf);
    return csrf;
  })

  .accessTokenPath('/token')
  .accessTokenParam('grant_type', 'authorization_code')
  // redirect_uri must match the one sent with the authPath
  .accessTokenParam('redirect_uri', function () {
    if (this._callbackPath) {
      return this._myHostname + this._callbackPath;
    }
  })

  .fetchOAuthUser( function (accessToken, accessTokenSecret, params) {
    var p = this.Promise();
    request({
      uri: this.apiHost() + "/account/info",
      headers: {
        "Authorization": "Bearer " + accessToken
      }
    }, function (err, res, data) {
      if (err) return p.fail(err);
      var oauthUser = JSON.parse(data);
      oauthUser.id = oauthUser.uid;
      p.fulfill(oauthUser);
    })
    return p;
  })
  .authCallbackDidErr( function (req) {
    var parsedUrl = url.parse(req.url, true);
    if (parsedUrl.query && parsedUrl.query.state !== req.cookies["dropbox.csrf"]) {
      return true;
    }
    if (parsedUrl.query && parsedUrl.query.error) {
      return true;
    }
    return parsedUrl.query && !!parsedUrl.query.not_approved;
  })

  // Over-write because state query param is used for CSRF token, not a
  // redirect path
  .sendResponse( function (res, data) {
    var req = data.req;
    var redirectTo = this._redirectPath;
    if (redirectTo) {
      this.redirect(res, redirectTo);
    } else {
      data.next();
    }
  });

  everyauth.dropbox.appId = function (appId) {
    this._appId = appId;
    setBasicAuth(this);
    return this;
  };

  everyauth.dropbox.appSecret = function (appSecret) {
    this._appSecret = appSecret;
    setBasicAuth(this);
    return this;
  };

  everyauth.dropbox.AuthCallbackError = AuthCallbackError;
  everyauth.dropbox.CsrfError = CsrfError;

  return everyauth.dropbox;
};

function AuthCallbackError(req) {
  var query = url.parse(req.url, true).query;


  Error.call(this);
  Error.captureStackTrace(this, AuthCallbackError);
  if (query && query.state !== req.cookies["dropbox.csrf"]) {
    this.name = 'AuthCallbackCsrfError';
    this.message = "CSRF Token Mismatch";
  } else {
    this.name = 'AuthCallbackError';
    this.message = query.error + "; " +  query.error_description;
  }
  this.req = req;
}

function CsrfError(req) {
  Error.call(this);
  Error.captureStackTrace(this, CsrfError);
  this.name = 'CsrfError';
  this.message = "CSRF Token mismatch";
  this.req = req;
}

function generateCsrfToken () {
  return crypto.randomBytes(16).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
}

function setBasicAuth (module) {
  if (module._appId && module._appSecret) {
    var auth = "Basic " +
      new Buffer(module._appId + ":" + module._appSecret).toString("base64");
    module.customHeaders({
      "Authorization": auth
    });
  }
}
