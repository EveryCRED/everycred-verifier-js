const path = require("node:path");

module.exports = {
  entry: "./dist/index.js",
  output: {
    filename: "index.bundle.js",
    path: path.resolve(__dirname, "dist"),
    library: {
      name: "EveryCredVerifier",
      type: "umd",
    },
    globalObject: "window",
  },
};