import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes, OctetString } from "@peculiar/asn1-schema";
import { OtherKeyAttribute } from "./other_key_attribute";
import { CMSVersion, KeyEncryptionAlgorithmIdentifier } from "./types";
export class KEKIdentifier {
    constructor(params = {}) {
        this.keyIdentifier = new OctetString();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: OctetString })
], KEKIdentifier.prototype, "keyIdentifier", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.GeneralizedTime, optional: true })
], KEKIdentifier.prototype, "date", void 0);
__decorate([
    AsnProp({ type: OtherKeyAttribute, optional: true })
], KEKIdentifier.prototype, "other", void 0);
export class KEKRecipientInfo {
    constructor(params = {}) {
        this.version = CMSVersion.v4;
        this.kekid = new KEKIdentifier();
        this.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier();
        this.encryptedKey = new OctetString();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], KEKRecipientInfo.prototype, "version", void 0);
__decorate([
    AsnProp({ type: KEKIdentifier })
], KEKRecipientInfo.prototype, "kekid", void 0);
__decorate([
    AsnProp({ type: KeyEncryptionAlgorithmIdentifier })
], KEKRecipientInfo.prototype, "keyEncryptionAlgorithm", void 0);
__decorate([
    AsnProp({ type: OctetString })
], KEKRecipientInfo.prototype, "encryptedKey", void 0);
