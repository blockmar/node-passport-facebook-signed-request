/**
 * Module dependencies.
 */
var Strategy = require('./lib/strategy');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;