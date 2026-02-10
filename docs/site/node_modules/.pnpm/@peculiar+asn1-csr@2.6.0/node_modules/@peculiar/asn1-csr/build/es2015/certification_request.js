import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { CertificationRequestInfo } from "./certification_request_info";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
export class CertificationRequest {
    constructor(params = {}) {
        this.certificationRequestInfo = new CertificationRequestInfo();
        this.signatureAlgorithm = new AlgorithmIdentifier();
        this.signature = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: CertificationRequestInfo, raw: true })
], CertificationRequest.prototype, "certificationRequestInfo", void 0);
__decorate([
    AsnProp({ type: AlgorithmIdentifier })
], CertificationRequest.prototype, "signatureAlgorithm", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.BitString })
], CertificationRequest.prototype, "signature", void 0);
