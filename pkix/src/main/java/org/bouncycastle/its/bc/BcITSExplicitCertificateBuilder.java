package org.bouncycastle.its.bc;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.oer.its.CertificateId;
import org.bouncycastle.oer.its.EccP256CurvePoint;
import org.bouncycastle.oer.its.PublicEncryptionKey;
import org.bouncycastle.oer.its.PublicVerificationKey;
import org.bouncycastle.oer.its.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public BcITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(signer, tbsCertificate);
    }

    public ITSCertificate build(CertificateId certificateId, ECPublicKeyParameters verificationKey, PublicEncryptionKey publicEncryptionKey)
    {
        tbsCertificateBuilder.setEncryptionKey(publicEncryptionKey);
        return build(certificateId, verificationKey);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey)
    {

        ECPoint q = verificationKey.getQ();
        return super.build(certificateId, PublicVerificationKey.builder()
            .ecdsaNistP256(EccP256CurvePoint.builder()
                .uncompressedP256(
                    q.getAffineXCoord().toBigInteger(),
                    q.getAffineYCoord().toBigInteger())
                .createEccP256CurvePoint())
            .createPublicVerificationKey());
    }
}
