"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.CredentialIssuerValidator = void 0;
var common_1 = require("../constants/common");
var messages_1 = require("../constants/messages");
var credential_util_1 = require("../utils/credential-util");
var logger_1 = require("../utils/logger");
var CredentialIssuerValidator = /** @class */ (function () {
    function CredentialIssuerValidator() {
    }
    CredentialIssuerValidator.prototype.validate = function (credentialData) {
        this.credential = credential_util_1.deepCloneData(credentialData);
        logger_1.logger(this.credential);
        this.validateCredentialIssuer();
        return true;
    };
    CredentialIssuerValidator.prototype.validateCredentialIssuer = function () {
        return __awaiter(this, void 0, Promise, function () {
            var issuerData, data;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        logger_1.logger(messages_1.Messages.ISSUER_VALIDATION_STARTED);
                        if (!credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.issuer)) return [3 /*break*/, 3];
                        issuerData = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.issuer);
                        if (!(issuerData && new URL(issuerData))) return [3 /*break*/, 2];
                        logger_1.logger(issuerData);
                        console.log("before");
                        return [4 /*yield*/, credential_util_1.getDataFromAPI(issuerData)];
                    case 1:
                        data = _a.sent();
                        console.log(data);
                        console.log("after");
                        _a.label = 2;
                    case 2: return [3 /*break*/, 3];
                    case 3: return [2 /*return*/, false];
                }
            });
        });
    };
    return CredentialIssuerValidator;
}());
exports.CredentialIssuerValidator = CredentialIssuerValidator;
