import { __decorate } from "tslib";
import { AsnProp, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
export class EncryptedData extends OctetString {
}
export class EncryptedPrivateKeyInfo {
    constructor(params = {}) {
        this.encryptionAlgorithm = new AlgorithmIdentifier();
        this.encryptedData = new EncryptedData();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AlgorithmIdentifier })
], EncryptedPrivateKeyInfo.prototype, "encryptionAlgorithm", void 0);
__decorate([
    AsnProp({ type: EncryptedData })
], EncryptedPrivateKeyInfo.prototype, "encryptedData", void 0);
