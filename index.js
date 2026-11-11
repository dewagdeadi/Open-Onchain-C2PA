// Node entry: everything. Workers import lib/worker.js instead (no Node built-ins).
module.exports = {
  ...require("./lib/core"),
  ...require("./lib/web"),
  ...require("./lib/arweave"),
  ...require("./lib/statements"),
  ...require("./lib/publish"),
  ...require("./lib/verify"),
  ...require("./lib/ans104"),
  ...require("./lib/arweave-tx"),
};
