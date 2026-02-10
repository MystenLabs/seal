import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes, OctetString } from "@peculiar/asn1-schema";
import { CMSVersion, KeyDerivationAlgorithmIdentifier, KeyEncryptionAlgorithmIdentifier, } from "./types";
export class PasswordRecipientInfo {
    constructor(params = {}) {
        this.version = CMSVersion.v0;
        this.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier();
        this.encryptedKey = new OctetString();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], PasswordRecipientInfo.prototype, "version", void 0);
__decorate([
    AsnProp({ type: KeyDerivationAlgorithmIdentifier, context: 0, optional: true })
], PasswordRecipientInfo.prototype, "keyDerivationAlgorithm", void 0);
__decorate([
    AsnProp({ type: KeyEncryptionAlgorithmIdentifier })
], PasswordRecipientInfo.prototype, "keyEncryptionAlgorithm", void 0);
__decorate([
    AsnProp({ type: OctetString })
], PasswordRecipientInfo.prototype, "encryptedKey", void 0);
