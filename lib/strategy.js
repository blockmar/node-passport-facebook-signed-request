/**
 * Module dependencies.
 */
var passport = require('passport'),
    util = require('util'),
    b64url = require('b64url'),
    crypto = require('crypto'),
    https = require('https');


/**
 * `FacebookSignedRequestStrategy` constructor.
 *
 * Options:
 *   - `clientID`      your Facebook application's App ID
 *   - `clientSecret`  your Facebook application's App Secret
 *
 * Examples:
 *
 *     passport.use(new FacebookSignedRequestStrategy(
 *       function(req, accessToken, profile, done) {
 *         User.findOne({ userid: profile.id }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function FacebookSignedRequestStrategy(options, verify) {
    if (!options || !options.clientSecret) {
        throw new Error('Facebook Signed Request Strategy authentication strategy requires facebook client secret');
    }
    if (!verify) {
        throw new Error('Facebook Signed Request Strategy authentication strategy requires a verify function');
    }

    this._passReqToCallback = options.passReqToCallback;

    passport.Strategy.call(this);

    this.name = 'facebook-signed-request';
    this._profileURL = options.profileURL || 'https://graph.facebook.com/me';
    this._verify = verify;
    this._clientSecret = options.clientSecret;
    this._enableProof = options.enableProof;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(FacebookSignedRequestStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Basic authorization
 * header.
 *
 * @param {Object} req
 * @api protected
 */
FacebookSignedRequestStrategy.prototype.authenticate = function(req) {

    var accessToken = req.body.access_token || req.query.access_token;
    var signedRequest = req.body.signed_request || req.query.signed_request;

    var self = this;

    if(!signedRequest || !accessToken) {
        self.fail(400);
    }

    self._parse_signed_request(signedRequest, function(err, decoded_signed_request) {

        if(err || !decoded_signed_request) {
            return self.error(err);
        }

        self.userProfile(accessToken, function(err, profile){

            if(err || !profile) {
                return self.error(err);
            }

            if(profile.id != decoded_signed_request.user_id) {
                return self.error(new Error("Something is fishy User id of signed request differs from user id of profile"));
            }

            function verified(err, user, info) {
                if (err) { return self.error(err); }
                if (!user) { return self.fail(info); }
                self.success(user);
            }

            if (self._passReqToCallback) {
                self._verify(req, accessToken, profile, verified);
            } else {
                self._verify(accessToken, profile, verified);
            }
        });
    });
}

FacebookSignedRequestStrategy.prototype._parse_signed_request = function(signed_request, callback) {

    var self = this;

    var encoded_data = signed_request.split('.', 2);

    if(encoded_data.length != 2) {
        callback(new Error("Invalid data in signed request"));
    }

    var signature = encoded_data[0];
    var json = b64url.decode(encoded_data[1]);
    var data = JSON.parse(json);

    // check algorithm
    if (!data.algorithm || (data.algorithm.toUpperCase() != 'HMAC-SHA256')) {
        callback(new Error("Unknown algorithm: Expected HMAC-SHA256 Got: " + data.algorithm.toUpperCase()));
        return;
    }

    // Check signature
    var expected_signature = crypto.createHmac('sha256', self._clientSecret).update(encoded_data[1]).digest('base64').replace(/\+/g,'-').replace(/\//g,'_').replace('=','');

    if (signature !== expected_signature) {
        callback(new Error("Bad request signature"));
        return;
    }

    callback(null, data);
};

/**
 *
 * Modified from from https://github.com/drudge/passport-facebook-token/blob/master/lib/passport-facebook-token/strategy.js
 *
 * Retrieve user profile from Facebook.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `facebook`
 *   - `id`               the user's Facebook ID
 *   - `username`         the user's Facebook username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Facebook
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
FacebookSignedRequestStrategy.prototype.userProfile = function(accessToken, done) {

    var url = this._profileURL + "?access_token=" + accessToken;
    https.get(url, function(res) {
        if(res.statusCode >= 400) {
            done(new Error("Invalid response code: " + res.statusCode))
        } else {
            var data = '';

            res.on('data', function (chunk){
                data += chunk;
            });

            res.on('end',function(){
                try {
                    var json = JSON.parse(data);

                    var profile = { provider: 'facebook' };

                    profile.id = json.id;
                    profile.username = json.username;
                    profile.displayName = json.name;
                    profile.name = {
                        familyName: json.last_name,
                        givenName: json.first_name,
                        middleName: json.middle_name
                    };
                    profile.gender = json.gender;
                    profile.profileUrl = json.link;
                    profile.emails = [{ value: json.email }];

                    profile._raw = data;
                    profile._json = json;

                    done(null, profile);
                } catch(e) {
                    done(e);
                }
            });
        }
    }).on('error', function(e) {
            done(e);
        });
}

/**
 * Expose `FacebookTokenStrategy`.
 */
module.exports = FacebookSignedRequestStrategy;