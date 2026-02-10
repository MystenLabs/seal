import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { id_pkcs_9 } from "./types";
export class CertBag {
    constructor(params = {}) {
        this.certId = "";
        this.certValue = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier })
], CertBag.prototype, "certId", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.Any, context: 0 })
], CertBag.prototype, "certValue", void 0);
export const id_certTypes = `${id_pkcs_9}.22`;
export const id_x509Certificate = `${id_certTypes}.1`;
export const id_sdsiCertificate = `${id_certTypes}.2`;
