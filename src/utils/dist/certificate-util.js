"use strict";
exports.__esModule = true;
exports.getDataFromKey = exports.isKeyPresent = exports.deepCloneData = void 0;
var lodash_1 = require("lodash");
function deepCloneData(data) {
    if (data)
        return lodash_1.cloneDeep(data);
}
exports.deepCloneData = deepCloneData;
function isKeyPresent(data, key) {
    return data && key ? lodash_1.has(data, key) : false;
}
exports.isKeyPresent = isKeyPresent;
function getDataFromKey(data, key, defaultValue) {
    if (defaultValue === void 0) { defaultValue = null; }
    return lodash_1.get(data, key, defaultValue);
}
exports.getDataFromKey = getDataFromKey;
