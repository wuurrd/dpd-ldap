var ldap = require('ldapjs');
var util = require('util');

function ldap_login(client, username, password, cb) {
  var NO_BIND_ERROR = 'a successful bind';
  client.bind(
    username, password,
    function(err, user){
      if (err) {
        client.unbind();
        return cb(false);
      }
      client.search(
        'dc=example, dc=com',
        { scope: 'sub', filter: 'sAMAccountName=:user' },
        function(error, search_result) {
          if (error) {
            client.unbind();
            return cb(false);
          }
          search_result.on('error', function(ldap_err) {
              client.unbind();
              if (ldap_err.message.indexOf(NO_BIND_ERROR) != -1) {
                return cb(false);
              }
              else {
                return cb(true);
              }
          });
        });
    });
}

module.exports = ldap_login;
