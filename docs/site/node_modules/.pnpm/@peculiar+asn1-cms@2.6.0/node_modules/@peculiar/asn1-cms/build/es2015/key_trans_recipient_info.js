import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, OctetString } from "@peculiar/asn1-schema";
import { CMSVersion, KeyEncryptionAlgorithmIdentifier } from "./types";
import { IssuerAndSerialNumber } from "./issuer_and_serial_number";
import { SubjectKeyIdentifier } from "@peculiar/asn1-x509";
let RecipientIdentifier = class RecipientIdentifier {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
__decorate([
    AsnProp({ type: SubjectKeyIdentifier, context: 0, implicit: true })
], RecipientIdentifier.prototype, "subjectKeyIdentifier", void 0);
__decorate([
    AsnProp({ type: IssuerAndSerialNumber })
], RecipientIdentifier.prototype, "issuerAndSerialNumber", void 0);
RecipientIdentifier = __decorate([
    AsnType({ type: AsnTypeTypes.Choice })
], RecipientIdentifier);
export { RecipientIdentifier };
export class KeyTransRecipientInfo {
    constructor(params = {}) {
        this.version = CMSVersion.v0;
        this.rid = new RecipientIdentifier();
        this.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier();
        this.encryptedKey = new OctetString();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], KeyTransRecipientInfo.prototype, "version", void 0);
__decorate([
    AsnProp({ type: RecipientIdentifier })
], KeyTransRecipientInfo.prototype, "rid", void 0);
__decorate([
    AsnProp({ type: KeyEncryptionAlgorithmIdentifier })
], KeyTransRecipientInfo.prototype, "keyEncryptionAlgorithm", void 0);
__decorate([
    AsnProp({ type: OctetString })
], KeyTransRecipientInfo.prototype, "encryptedKey", void 0);
