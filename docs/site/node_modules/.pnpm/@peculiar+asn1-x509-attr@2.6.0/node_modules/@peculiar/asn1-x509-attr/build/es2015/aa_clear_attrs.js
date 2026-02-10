import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { GeneralName, Attribute } from "@peculiar/asn1-x509";
export class ACClearAttrs {
    constructor(params = {}) {
        this.acIssuer = new GeneralName();
        this.acSerial = 0;
        this.attrs = [];
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: GeneralName })
], ACClearAttrs.prototype, "acIssuer", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], ACClearAttrs.prototype, "acSerial", void 0);
__decorate([
    AsnProp({ type: Attribute, repeated: "sequence" })
], ACClearAttrs.prototype, "attrs", void 0);
