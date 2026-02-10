import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { AttributeCertificateInfo } from "./attribute_certificate_info";
export class AttributeCertificate {
    constructor(params = {}) {
        this.acinfo = new AttributeCertificateInfo();
        this.signatureAlgorithm = new AlgorithmIdentifier();
        this.signatureValue = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AttributeCertificateInfo })
], AttributeCertificate.prototype, "acinfo", void 0);
__decorate([
    AsnProp({ type: AlgorithmIdentifier })
], AttributeCertificate.prototype, "signatureAlgorithm", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.BitString })
], AttributeCertificate.prototype, "signatureValue", void 0);
