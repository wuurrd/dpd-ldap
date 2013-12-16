var ldap = require('ldapjs')
  , ldap_login = require('./ldap')
  , validation = require('validation')
  , util = require('util')
  , Collection = require('deployd/lib/resources/collection')
  , db = require('deployd/lib/db')
  , EventEmitter = require('events').EventEmitter
  , uuid = require('deployd/lib/util/uuid')
  , debug = require('debug')('ldap-user-collection');

/**
 * A `LDAPUserCollection` adds user authentication to the Collection resource.
 *
 * Settings:
 *
 *   - `path`                the base path a resource should handle
 *   - `config.properties`   the properties of objects the collection should store
 *   - `db`                  the database a collection will use for persistence
 *
 * @param {Object} options
 */

function LDAPUserCollection(name, options) {
  Collection.apply(this, arguments);

  var config = this.config;

  if(!this.properties) {
    this.properties = {};
  }

  // username is required
  this.properties.username = this.properties.username || {type: 'string'};
  this.properties.username.required = true;
  this.client = ldap.createClient({url: this.config.ldapUrl});
}

util.inherits(LDAPUserCollection, Collection);

LDAPUserCollection.dashboard = Collection.dashboard;
LDAPUserCollection.events    = Collection.events;

/**
 * Handle an incoming http `req` and `res` and execute
 * the correct `Store` proxy function based on `req.method`.
 *
 *
 * @param {ServerRequest} req
 * @param {ServerResponse} res
 */

LDAPUserCollection.prototype.handle = function (ctx) {
  var uc = this;
  if (ctx.req.method == "GET" && (ctx.url === '/count' || ctx.url.indexOf('/index-of') === 0)) {
    return Collection.prototype.handle.apply(uc, arguments);
  }

  if(ctx.url === '/logout') {
    if (ctx.res.cookies) ctx.res.cookies.set('sid', null);
    ctx.session.remove(ctx.done);
    return;
  }

  // set id one wasnt provided in the query
  ctx.query.id = ctx.query.id || this.parseId(ctx) || (ctx.body && ctx.body.id);

  switch(ctx.req.method) {
    case 'GET':
      if(ctx.url === '/me') {
        debug('session %j', ctx.session.data);
        if(!(ctx.session && ctx.session.data && ctx.session.data.uid)) {
          ctx.res.statusCode = 204;
          return ctx.done();
        }

        ctx.query = {id: ctx.session.data.uid};

        return this.find(ctx, ctx.done);
      }

      this.find(ctx, ctx.done);
    break;
    case 'POST':
      if(ctx.url === '/login') {
        var path = this.path
          , credentials = ctx.req.body || {};

        debug('trying to login as %s', credentials.username);
        return uc.ldapLogin(ctx, uc, path);
        break;
      }
      /* falls through */
    case 'PUT':
      var isSelf = ctx.session.user && ctx.session.user.id === ctx.query.id || (ctx.body && ctx.body.id);
      if ((ctx.query.id || ctx.body.id) && ctx.body && !isSelf && !ctx.session.isRoot && !ctx.req.internal) {
        delete ctx.body.username;
      }

      if(ctx.query.id || ctx.body.id) {
        this.save(ctx, ctx.done);
      } else {
        this.store.first({username: ctx.body.username}, function (err, u) {
          if(u) return ctx.done({errors: {username: 'is already in use'}});
          uc.save(ctx, ctx.done);
        });
      }
    break;
    case 'DELETE':
      debug('removing', ctx.query, ctx.done);
      this.remove(ctx, ctx.done);
    break;
  }
};

LDAPUserCollection.prototype.ldapLogin = function (ctx, uc, path) {
  debug('LDAP Login called', uc.config.ldapUrl);
  function addUser() {
    function done(err, user) {
      if (user) {
        ctx.session.set({path: path, uid: user.id}).save(ctx.done);
        return;
      }
      return ctx.done(err);
    }
    // If query id is set - save will do a put rather than a post.
    ctx.query.id = null;
    return uc.save(ctx, done);
  }
  ldap_login(uc.client, ctx.body.username, ctx.body.password, function (authenticated) {
    if (!authenticated) {
      ctx.res.statusCode = 401;
      return ctx.done('bad credentials');
    }
    else {
      addUser();
    }
  });
};

  LDAPUserCollection.prototype.handleSession = function (ctx, fn) {
  // called when any session has been created
  var session = ctx.session
    , path = this.path;

  if(session && session.data && session.data.path == path && session.data.uid) {
    this.store.find({id: session.data.uid}, function(err, user) {
      session.user = user;
      fn(err);
    });
  } else {
    fn();
  }
};

LDAPUserCollection.label = 'LDAP Users Collection';
LDAPUserCollection.defaultPath = '/users';

LDAPUserCollection.prototype.clientGenerationGet = ['me'];
LDAPUserCollection.prototype.clientGenerationExec = ['login', 'logout'];

module.exports = LDAPUserCollection;
