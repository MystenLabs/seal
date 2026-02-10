var RecipientEncryptedKeys_1;
import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes, AsnArray, AsnType, AsnTypeTypes, OctetString, } from "@peculiar/asn1-schema";
import { CMSVersion, KeyEncryptionAlgorithmIdentifier } from "./types";
import { IssuerAndSerialNumber } from "./issuer_and_serial_number";
import { AlgorithmIdentifier, SubjectKeyIdentifier } from "@peculiar/asn1-x509";
import { OtherKeyAttribute } from "./other_key_attribute";
export class RecipientKeyIdentifier {
    constructor(params = {}) {
        this.subjectKeyIdentifier = new SubjectKeyIdentifier();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: SubjectKeyIdentifier })
], RecipientKeyIdentifier.prototype, "subjectKeyIdentifier", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.GeneralizedTime, optional: true })
], RecipientKeyIdentifier.prototype, "date", void 0);
__decorate([
    AsnProp({ type: OtherKeyAttribute, optional: true })
], RecipientKeyIdentifier.prototype, "other", void 0);
let KeyAgreeRecipientIdentifier = class KeyAgreeRecipientIdentifier {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
__decorate([
    AsnProp({ type: RecipientKeyIdentifier, context: 0, implicit: true, optional: true })
], KeyAgreeRecipientIdentifier.prototype, "rKeyId", void 0);
__decorate([
    AsnProp({ type: IssuerAndSerialNumber, optional: true })
], KeyAgreeRecipientIdentifier.prototype, "issuerAndSerialNumber", void 0);
KeyAgreeRecipientIdentifier = __decorate([
    AsnType({ type: AsnTypeTypes.Choice })
], KeyAgreeRecipientIdentifier);
export { KeyAgreeRecipientIdentifier };
export class RecipientEncryptedKey {
    constructor(params = {}) {
        this.rid = new KeyAgreeRecipientIdentifier();
        this.encryptedKey = new OctetString();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: KeyAgreeRecipientIdentifier })
], RecipientEncryptedKey.prototype, "rid", void 0);
__decorate([
    AsnProp({ type: OctetString })
], RecipientEncryptedKey.prototype, "encryptedKey", void 0);
let RecipientEncryptedKeys = RecipientEncryptedKeys_1 = class RecipientEncryptedKeys extends AsnArray {
    constructor(items) {
        super(items);
        Object.setPrototypeOf(this, RecipientEncryptedKeys_1.prototype);
    }
};
RecipientEncryptedKeys = RecipientEncryptedKeys_1 = __decorate([
    AsnType({ type: AsnTypeTypes.Sequence, itemType: RecipientEncryptedKey })
], RecipientEncryptedKeys);
export { RecipientEncryptedKeys };
export class OriginatorPublicKey {
    constructor(params = {}) {
        this.algorithm = new AlgorithmIdentifier();
        this.publicKey = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AlgorithmIdentifier })
], OriginatorPublicKey.prototype, "algorithm", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.BitString })
], OriginatorPublicKey.prototype, "publicKey", void 0);
let OriginatorIdentifierOrKey = class OriginatorIdentifierOrKey {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
__decorate([
    AsnProp({ type: SubjectKeyIdentifier, context: 0, implicit: true, optional: true })
], OriginatorIdentifierOrKey.prototype, "subjectKeyIdentifier", void 0);
__decorate([
    AsnProp({ type: OriginatorPublicKey, context: 1, implicit: true, optional: true })
], OriginatorIdentifierOrKey.prototype, "originatorKey", void 0);
__decorate([
    AsnProp({ type: IssuerAndSerialNumber, optional: true })
], OriginatorIdentifierOrKey.prototype, "issuerAndSerialNumber", void 0);
OriginatorIdentifierOrKey = __decorate([
    AsnType({ type: AsnTypeTypes.Choice })
], OriginatorIdentifierOrKey);
export { OriginatorIdentifierOrKey };
export class KeyAgreeRecipientInfo {
    constructor(params = {}) {
        this.version = CMSVersion.v3;
        this.originator = new OriginatorIdentifierOrKey();
        this.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier();
        this.recipientEncryptedKeys = new RecipientEncryptedKeys();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], KeyAgreeRecipientInfo.prototype, "version", void 0);
__decorate([
    AsnProp({ type: OriginatorIdentifierOrKey, context: 0 })
], KeyAgreeRecipientInfo.prototype, "originator", void 0);
__decorate([
    AsnProp({ type: OctetString, context: 1, optional: true })
], KeyAgreeRecipientInfo.prototype, "ukm", void 0);
__decorate([
    AsnProp({ type: KeyEncryptionAlgorithmIdentifier })
], KeyAgreeRecipientInfo.prototype, "keyEncryptionAlgorithm", void 0);
__decorate([
    AsnProp({ type: RecipientEncryptedKeys })
], KeyAgreeRecipientInfo.prototype, "recipientEncryptedKeys", void 0);
