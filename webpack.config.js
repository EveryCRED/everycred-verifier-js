const path = require("path");

module.exports = {
  entry: "./dist/index.js",
  output: {
    filename: "index.bundle.js",
    path: path.resolve(__dirname, "dist"),
    libraryTarget: "window",
  },
};