var SignerInfos_1;
import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes, AsnArray, AsnType, AsnTypeTypes, OctetString, } from "@peculiar/asn1-schema";
import { SignerIdentifier } from "./signer_identifier";
import { CMSVersion, SignatureAlgorithmIdentifier, DigestAlgorithmIdentifier } from "./types";
import { Attribute } from "./attribute";
export class SignerInfo {
    constructor(params = {}) {
        this.version = CMSVersion.v0;
        this.sid = new SignerIdentifier();
        this.digestAlgorithm = new DigestAlgorithmIdentifier();
        this.signatureAlgorithm = new SignatureAlgorithmIdentifier();
        this.signature = new OctetString();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], SignerInfo.prototype, "version", void 0);
__decorate([
    AsnProp({ type: SignerIdentifier })
], SignerInfo.prototype, "sid", void 0);
__decorate([
    AsnProp({ type: DigestAlgorithmIdentifier })
], SignerInfo.prototype, "digestAlgorithm", void 0);
__decorate([
    AsnProp({
        type: Attribute,
        repeated: "set",
        context: 0,
        implicit: true,
        optional: true,
        raw: true,
    })
], SignerInfo.prototype, "signedAttrs", void 0);
__decorate([
    AsnProp({ type: SignatureAlgorithmIdentifier })
], SignerInfo.prototype, "signatureAlgorithm", void 0);
__decorate([
    AsnProp({ type: OctetString })
], SignerInfo.prototype, "signature", void 0);
__decorate([
    AsnProp({ type: Attribute, repeated: "set", context: 1, implicit: true, optional: true })
], SignerInfo.prototype, "unsignedAttrs", void 0);
let SignerInfos = SignerInfos_1 = class SignerInfos extends AsnArray {
    constructor(items) {
        super(items);
        Object.setPrototypeOf(this, SignerInfos_1.prototype);
    }
};
SignerInfos = SignerInfos_1 = __decorate([
    AsnType({ type: AsnTypeTypes.Set, itemType: SignerInfo })
], SignerInfos);
export { SignerInfos };
