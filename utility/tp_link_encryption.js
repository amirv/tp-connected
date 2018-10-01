// Polyfills
jQuery = {};
$ = {};
navigator = {};
window = {
  crypto: function(n) {
    return Array.apply(null, Array(n)).map(function() {
      return Math.random();
    });
  }
};

// Function used by the python code
function enc(val, nn, ee) {
  var result = jQuery.rsa.encrypt(val, nn, ee);
  return result;
}

/*********
 * Copy below the content of encrypt.js, you can find it
 * inside the router login page.
 * The file is not included
 *********/
