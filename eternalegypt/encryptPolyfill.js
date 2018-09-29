global.jQuery = {};
global.$ = {};
global.navigator = {};
global.window = {};
window.crypto = {
  getRandomValues: n => [...Array(n).keys()].map(() => Math.random())
};

const encrypt = require("./encrypt");

if (process.argv.length === 5) {
  const encrypted = global.jQuery.rsa.encrypt(
    process.argv[2],
    process.argv[3],
    process.argv[4]
  );
  console.log(encrypted);
} else {
  console.error("error argv");
}
