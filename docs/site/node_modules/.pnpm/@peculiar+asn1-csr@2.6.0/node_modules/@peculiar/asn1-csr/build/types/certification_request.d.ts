import { CertificationRequestInfo } from "./certification_request_info";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
/**
 * ```asn1
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo CertificationRequestInfo,
 *   signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature          BIT STRING
 * }
 * ```
 */
export declare class CertificationRequest {
    certificationRequestInfo: CertificationRequestInfo;
    certificationRequestInfoRaw?: ArrayBuffer;
    signatureAlgorithm: AlgorithmIdentifier;
    signature: ArrayBuffer;
    constructor(params?: Partial<CertificationRequest>);
}
