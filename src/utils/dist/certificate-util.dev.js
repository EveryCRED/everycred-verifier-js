"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.deepCloneData = deepCloneData;
exports.isKeyPresent = isKeyPresent;
exports.getDataFromKey = getDataFromKey;

var _lodash = require("lodash");

function deepCloneData(data) {
  if (data) return (0, _lodash.cloneDeep)(data);
}

function isKeyPresent(data, key) {
  return data && key ? (0, _lodash.has)(data, key) : false;
}

function getDataFromKey(data, key) {
  return (0, _lodash.get)(data, key, null);
}