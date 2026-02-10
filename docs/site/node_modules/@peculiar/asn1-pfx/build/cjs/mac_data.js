"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MacData = void 0;
const tslib_1 = require("tslib");
const asn1_rsa_1 = require("@peculiar/asn1-rsa");
const asn1_schema_1 = require("@peculiar/asn1-schema");
class MacData {
    constructor(params = {}) {
        this.mac = new asn1_rsa_1.DigestInfo();
        this.macSalt = new asn1_schema_1.OctetString();
        this.iterations = 1;
        Object.assign(this, params);
    }
}
exports.MacData = MacData;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_rsa_1.DigestInfo })
], MacData.prototype, "mac", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.OctetString })
], MacData.prototype, "macSalt", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.Integer, defaultValue: 1 })
], MacData.prototype, "iterations", void 0);
