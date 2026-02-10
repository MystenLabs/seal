"use strict";
var RecipientEncryptedKeys_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyAgreeRecipientInfo = exports.OriginatorIdentifierOrKey = exports.OriginatorPublicKey = exports.RecipientEncryptedKeys = exports.RecipientEncryptedKey = exports.KeyAgreeRecipientIdentifier = exports.RecipientKeyIdentifier = void 0;
const tslib_1 = require("tslib");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const types_1 = require("./types");
const issuer_and_serial_number_1 = require("./issuer_and_serial_number");
const asn1_x509_1 = require("@peculiar/asn1-x509");
const other_key_attribute_1 = require("./other_key_attribute");
class RecipientKeyIdentifier {
    constructor(params = {}) {
        this.subjectKeyIdentifier = new asn1_x509_1.SubjectKeyIdentifier();
        Object.assign(this, params);
    }
}
exports.RecipientKeyIdentifier = RecipientKeyIdentifier;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_x509_1.SubjectKeyIdentifier })
], RecipientKeyIdentifier.prototype, "subjectKeyIdentifier", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.GeneralizedTime, optional: true })
], RecipientKeyIdentifier.prototype, "date", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: other_key_attribute_1.OtherKeyAttribute, optional: true })
], RecipientKeyIdentifier.prototype, "other", void 0);
let KeyAgreeRecipientIdentifier = class KeyAgreeRecipientIdentifier {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
exports.KeyAgreeRecipientIdentifier = KeyAgreeRecipientIdentifier;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: RecipientKeyIdentifier, context: 0, implicit: true, optional: true })
], KeyAgreeRecipientIdentifier.prototype, "rKeyId", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: issuer_and_serial_number_1.IssuerAndSerialNumber, optional: true })
], KeyAgreeRecipientIdentifier.prototype, "issuerAndSerialNumber", void 0);
exports.KeyAgreeRecipientIdentifier = KeyAgreeRecipientIdentifier = tslib_1.__decorate([
    (0, asn1_schema_1.AsnType)({ type: asn1_schema_1.AsnTypeTypes.Choice })
], KeyAgreeRecipientIdentifier);
class RecipientEncryptedKey {
    constructor(params = {}) {
        this.rid = new KeyAgreeRecipientIdentifier();
        this.encryptedKey = new asn1_schema_1.OctetString();
        Object.assign(this, params);
    }
}
exports.RecipientEncryptedKey = RecipientEncryptedKey;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: KeyAgreeRecipientIdentifier })
], RecipientEncryptedKey.prototype, "rid", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.OctetString })
], RecipientEncryptedKey.prototype, "encryptedKey", void 0);
let RecipientEncryptedKeys = RecipientEncryptedKeys_1 = class RecipientEncryptedKeys extends asn1_schema_1.AsnArray {
    constructor(items) {
        super(items);
        Object.setPrototypeOf(this, RecipientEncryptedKeys_1.prototype);
    }
};
exports.RecipientEncryptedKeys = RecipientEncryptedKeys;
exports.RecipientEncryptedKeys = RecipientEncryptedKeys = RecipientEncryptedKeys_1 = tslib_1.__decorate([
    (0, asn1_schema_1.AsnType)({ type: asn1_schema_1.AsnTypeTypes.Sequence, itemType: RecipientEncryptedKey })
], RecipientEncryptedKeys);
class OriginatorPublicKey {
    constructor(params = {}) {
        this.algorithm = new asn1_x509_1.AlgorithmIdentifier();
        this.publicKey = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
exports.OriginatorPublicKey = OriginatorPublicKey;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_x509_1.AlgorithmIdentifier })
], OriginatorPublicKey.prototype, "algorithm", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.BitString })
], OriginatorPublicKey.prototype, "publicKey", void 0);
let OriginatorIdentifierOrKey = class OriginatorIdentifierOrKey {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
exports.OriginatorIdentifierOrKey = OriginatorIdentifierOrKey;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_x509_1.SubjectKeyIdentifier, context: 0, implicit: true, optional: true })
], OriginatorIdentifierOrKey.prototype, "subjectKeyIdentifier", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: OriginatorPublicKey, context: 1, implicit: true, optional: true })
], OriginatorIdentifierOrKey.prototype, "originatorKey", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: issuer_and_serial_number_1.IssuerAndSerialNumber, optional: true })
], OriginatorIdentifierOrKey.prototype, "issuerAndSerialNumber", void 0);
exports.OriginatorIdentifierOrKey = OriginatorIdentifierOrKey = tslib_1.__decorate([
    (0, asn1_schema_1.AsnType)({ type: asn1_schema_1.AsnTypeTypes.Choice })
], OriginatorIdentifierOrKey);
class KeyAgreeRecipientInfo {
    constructor(params = {}) {
        this.version = types_1.CMSVersion.v3;
        this.originator = new OriginatorIdentifierOrKey();
        this.keyEncryptionAlgorithm = new types_1.KeyEncryptionAlgorithmIdentifier();
        this.recipientEncryptedKeys = new RecipientEncryptedKeys();
        Object.assign(this, params);
    }
}
exports.KeyAgreeRecipientInfo = KeyAgreeRecipientInfo;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.Integer })
], KeyAgreeRecipientInfo.prototype, "version", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: OriginatorIdentifierOrKey, context: 0 })
], KeyAgreeRecipientInfo.prototype, "originator", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.OctetString, context: 1, optional: true })
], KeyAgreeRecipientInfo.prototype, "ukm", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: types_1.KeyEncryptionAlgorithmIdentifier })
], KeyAgreeRecipientInfo.prototype, "keyEncryptionAlgorithm", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: RecipientEncryptedKeys })
], KeyAgreeRecipientInfo.prototype, "recipientEncryptedKeys", void 0);
