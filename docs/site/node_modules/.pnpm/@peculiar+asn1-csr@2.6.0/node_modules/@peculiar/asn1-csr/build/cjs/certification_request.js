"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificationRequest = void 0;
const tslib_1 = require("tslib");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const certification_request_info_1 = require("./certification_request_info");
const asn1_x509_1 = require("@peculiar/asn1-x509");
class CertificationRequest {
    constructor(params = {}) {
        this.certificationRequestInfo = new certification_request_info_1.CertificationRequestInfo();
        this.signatureAlgorithm = new asn1_x509_1.AlgorithmIdentifier();
        this.signature = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
exports.CertificationRequest = CertificationRequest;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: certification_request_info_1.CertificationRequestInfo, raw: true })
], CertificationRequest.prototype, "certificationRequestInfo", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_x509_1.AlgorithmIdentifier })
], CertificationRequest.prototype, "signatureAlgorithm", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.BitString })
], CertificationRequest.prototype, "signature", void 0);
