const path = require("path");

module.exports = {
  entry: "./dist/index.js",
  output: {
    filename: "everycred-verifier.js",
    path: path.resolve(__dirname, "dist"),
    libraryTarget: "window",
  },
};