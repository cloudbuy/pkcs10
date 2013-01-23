package ssl

import (
    "crypto"
    "crypto/dsa"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "errors"
    "io"
    "math/big"
)

var (
    oidAttrUnstructuredName  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2}
    oidAttrChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

type CsrAttribute int

const (
    CsrAttrUnknown CsrAttribute = iota
    CsrAttrUnstructuredName
    CsrAttrChallengePassword
)

type pkcs10 struct {
    Info pkcs10Info
    Algo pkix.AlgorithmIdentifier
    Sig  asn1.BitString
}

type pkcs10Info struct {
    Version     int
    Subject     pkix.RDNSequence
    SubjectInfo publicKeyInfo
    Attributes  asn1.RawValue
}

type publicKeyInfo struct {
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

type attribute struct {
    Name  asn1.ObjectIdentifier
    Value asn1.RawValue
}

type Attribute struct {
    Name  CsrAttribute
    Value interface{}
}

type CertificationRequest struct {
    Version             int
    Subject             pkix.Name

    SubjectKeyAlgorithm x509.PublicKeyAlgorithm
    SubjectKey          interface{}

    SignatureAlgorithm  x509.SignatureAlgorithm
    Signature           []byte

    Attributes          []*Attribute
}

func CreateCertificateRequest(rand io.Reader, csr *CertificationRequest, pub interface{}, priv interface{}) ([]byte, error) {
    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, errors.New("pkcs10: non-RSA public keys not supported")
    }

    rsaPriv, ok := priv.(*rsa.PrivateKey)
    if !ok {
        return nil, errors.New("x509: non-RSA private keys not supported")
    }

    if rsaPriv != nil {
    }

    asn1PublicKey, err := asn1.Marshal(rsaPublicKey{
        N: rsaPub.N,
        E: rsaPub.E,
    })
    if err != nil {
        return nil, err
    }

    encodedPublicKey := asn1.BitString{BitLength: len(asn1PublicKey) * 8, Bytes: asn1PublicKey}

    var p pkcs10
    p.Info.Subject = csr.Subject.ToRDNSequence()
    p.Info.Version = csr.Version
    p.Info.SubjectInfo.Algorithm = pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRsa}
    p.Info.SubjectInfo.PublicKey = encodedPublicKey
    p.Info.Attributes = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, FullBytes: []byte{160, 0}}

    pkcsInfoContents, err := asn1.Marshal(p.Info)
    if err != nil {
        return nil, err
    }

    h := sha1.New()
    h.Write(pkcsInfoContents)
    digest := h.Sum(nil)

    signature, err := rsa.SignPKCS1v15(rand, rsaPriv, crypto.SHA1, digest)
    if err != nil {
        return nil, err
    }

    p.Algo = pkix.AlgorithmIdentifier{Algorithm: oidSignatureSHA1WithRSA}
    p.Sig = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}

    return asn1.Marshal(p)
}

func ParsePKCS10CSR(der []byte) (csr *CertificationRequest, err error) {
    var p pkcs10
    if _, err := asn1.Unmarshal(der, &p); err != nil {
        return nil, err
    }

    certReq := &CertificationRequest{
        Version:            p.Info.Version,
        Signature:          p.Sig.Bytes,
        SignatureAlgorithm: getSignatureAlgorithmFromOID(p.Algo.Algorithm),
    }

    certReq.SubjectKeyAlgorithm = getPublicKeyAlgorithmFromOID(p.Info.SubjectInfo.Algorithm.Algorithm)

    pubKey, err := parsePublicKey(certReq.SubjectKeyAlgorithm, &p.Info.SubjectInfo)
    if err != nil {
        return nil, err
    }
    certReq.SubjectKey = pubKey
    certReq.Subject.FillFromRDNSequence(&p.Info.Subject)

    rest := p.Info.Attributes.Bytes
    for {
        if len(rest) == 0 {
            break
        }

        var a attribute
        rest, err = asn1.Unmarshal(rest, &a)
        if err != nil {
            return nil, err
        }

        var i interface{}
        _, err := asn1.Unmarshal(a.Value.Bytes, &i)
        if err != nil {
            return nil, err
        }

        attr := &Attribute{
            Name:  getAttributeNameFromOID(a.Name),
            Value: i,
        }

        certReq.Attributes = append(certReq.Attributes, attr)
    }

    return certReq, nil
}

func getAttributeNameFromOID(oid asn1.ObjectIdentifier) CsrAttribute {
    switch {
    case oid.Equal(oidAttrUnstructuredName):
        return CsrAttrUnstructuredName
    case oid.Equal(oidAttrChallengePassword):
        return CsrAttrChallengePassword
    }
    return CsrAttrUnknown
}

// The following code is lifted straight from the source of the x509.go file since
// there is no point implementing my own solution and there isn't any way to access
// it since its not exported. If at some point in time this is included in the stdlib
// then it can be removed or some other solution can be produced.
var (
    oidSignatureMD2WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
    oidSignatureMD5WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
    oidSignatureSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
    oidSignatureSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
    oidSignatureSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
    oidSignatureSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
    oidSignatureDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
    oidSignatureDSAWithSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 4, 3, 2}
)

func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
    switch {
    case oid.Equal(oidSignatureMD2WithRSA):
        return x509.MD2WithRSA
    case oid.Equal(oidSignatureMD5WithRSA):
        return x509.MD5WithRSA
    case oid.Equal(oidSignatureSHA1WithRSA):
        return x509.SHA1WithRSA
    case oid.Equal(oidSignatureSHA256WithRSA):
        return x509.SHA256WithRSA
    case oid.Equal(oidSignatureSHA384WithRSA):
        return x509.SHA384WithRSA
    case oid.Equal(oidSignatureSHA512WithRSA):
        return x509.SHA512WithRSA
    case oid.Equal(oidSignatureDSAWithSHA1):
        return x509.DSAWithSHA1
    case oid.Equal(oidSignatureDSAWithSHA256):
        return x509.DSAWithSHA256
    }
    return x509.UnknownSignatureAlgorithm
}

var (
    oidPublicKeyRsa = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
    oidPublicKeyDsa = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
    switch {
    case oid.Equal(oidPublicKeyRsa):
        return x509.RSA
    case oid.Equal(oidPublicKeyDsa):
        return x509.DSA
    }
    return x509.UnknownPublicKeyAlgorithm
}

type dsaAlgorithmParameters struct {
    P, Q, G *big.Int
}

type rsaPublicKey struct {
    N *big.Int
    E int
}

func parsePublicKey(algo x509.PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
    asn1Data := keyData.PublicKey.RightAlign()
    switch algo {
    case x509.RSA:
        p := new(rsaPublicKey)
        _, err := asn1.Unmarshal(asn1Data, p)
        if err != nil {
            return nil, err
        }

        pub := &rsa.PublicKey{
            E: p.E,
            N: p.N,
        }
        return pub, nil
    case x509.DSA:
        var p *big.Int
        _, err := asn1.Unmarshal(asn1Data, &p)
        if err != nil {
            return nil, err
        }
        paramsData := keyData.Algorithm.Parameters.FullBytes
        params := new(dsaAlgorithmParameters)
        _, err = asn1.Unmarshal(paramsData, params)
        if err != nil {
            return nil, err
        }
        if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
            return nil, errors.New("zero or negative DSA parameter")
        }
        pub := &dsa.PublicKey{
            Parameters: dsa.Parameters{
                P: params.P,
                Q: params.Q,
                G: params.G,
            },
            Y: p,
        }
        return pub, nil
    default:
        return nil, nil
    }
    panic("unreachable")
}
