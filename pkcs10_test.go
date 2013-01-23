package ssl

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/hex"
//    "encoding/pem"
    "fmt"
//    "os"
    "testing"
)

var pkcs10PrivateKeyHex = `308204a30201000282010100c0b3200a7027c4a5f48049b9afe3ba9f95fe2bd483bdd67505d96503177a2702727077f91037d27f31a1697f4eeb2de092f477e95746f574adbcc45005e47dcf635ec66cf2870d518eb7fd0bb8693883421502ce3ef4a3304c820f12c192c0eba7eeac3f647303b1215dabb1da5976bc78c760dbe7ca4b31517b5be50b5ced4cf95ea144bec2cf6b2506a036cb9a1f901be7393b6b28af2017effb9a8bf9c5ff7a44dc46c99fbfa064b357b7b5314457488de483e794db785521de6d8c6fca28f3ed83c3648ef5ffa54f2f1b9fe87e708d214b20aa445125d6949243801fa27f821d7e10998dd60ff6fe001ea01c52074b49d59589b47661cf24aebb6eb243cf02030100010282010101206474556ad8f9a36d32fa239eab71c818d11683acced640b90a4bf4be942001b787bee5cf71dbe46440b004c9f58ae988c5bb184b78752db43ec88702ea9da75d8e9fe4b96b89713fe8f81b2c58bd2d241f11ddddb67eec6ff44ddec23981e4ada5b3c003f365d9189879b769936ef24ec8059bd76097fc2d783365ad05dc55348959d72ee7011a05935de004330d17ad40ff1650c3cfa3ffbeaebaf42d868998b207a80f4ea57b6b94db2079a261e092634f5958908b7330b724ba1cede8651b70b967d3000c87e9558b37b76d86ffa48024fa53a8c884cdd697d975681d395f865fa086db61bee2d2330650b75ecbbff61b581000992038e1b2608f72112102818100f686f56ae1ca245c79d330f0048ea9a44ccc56cc4dcd3c6755e2299623f474a964849b95561bd282c104a960222286368d71455d2e204bb47f2ba0d85ef67df89b2b1e11e85d6dc3a607d7fe6c15b10b2b64a654c92d179c8edb4af6e85d87b50ab1c7c2dc2446116b3fc25e974b76a770600a714a0705afae6922791f8e962702818100c81aad00d7026e08099512c1b364b8a9e8c69c26f1106c693c7d7b96aea5d452657695dea253da214914c8e60a3f13baeabd91b52e89a7f353f9893162ad601480c5a456ab6b961c0b90237fdb1802749c35418a2eaf58072ef0af8a27d85b3c10986f6424b55766fbbe4488f2797bda8d57b5d124110985ef2d9eb37757d61902818030b794d20d529c02e65434cc89aa039e234b12300783f256dd62f722e3721087d5045b969450a5360f9cb337fb26e56cec60a0fb7bfd07d8e074a7b17a7aad842e6dc3e07811d67a1e5a5875bfb83da75e68e271c8dbaf59d1e546182aed28bf3f20c8c01a2ed4e5e652d03f4f18ab97051f059143b6c589e52683987a02fc6b02818029d551d7bc1b78ef5b397c1b5caab0e46c92a0f08f3314c7076b605c07150a0753c8efda046bad4d8a1ebb45445d1d7dd5375e6fd753d5f5cbd77e3401e22715023acf79830ad1edf908e0330995c265a88685b622be6b93ccdf6a8362831bc7b9dc7465263b7713438bea7e0adb14e682e8144dadd1960117189d75fd7c32790281802ea5c82f8f09259a90e368fde67cf588d98ac4bc99df19c0f7286e324a87f073b9f60b69b782ab39b7553126221efa5b75d81c0c01026540430e402401b2ba2eec2ce46dbcf03ed793853d1bf6b39f07c3288444763c56e63388d1d5540d98e57c0216a39e2d14f8ba1d324e46516a0d5cdc06d8d7771104a4194ce0845b55f9`

var pkcs10CSRHex = `3082027030820158020100302b3129302706035504030c2064657631332e696e7465726e616c2e63616c6c6576612e756b706c632e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c0b3200a7027c4a5f48049b9afe3ba9f95fe2bd483bdd67505d96503177a2702727077f91037d27f31a1697f4eeb2de092f477e95746f574adbcc45005e47dcf635ec66cf2870d518eb7fd0bb8693883421502ce3ef4a3304c820f12c192c0eba7eeac3f647303b1215dabb1da5976bc78c760dbe7ca4b31517b5be50b5ced4cf95ea144bec2cf6b2506a036cb9a1f901be7393b6b28af2017effb9a8bf9c5ff7a44dc46c99fbfa064b357b7b5314457488de483e794db785521de6d8c6fca28f3ed83c3648ef5ffa54f2f1b9fe87e708d214b20aa445125d6949243801fa27f821d7e10998dd60ff6fe001ea01c52074b49d59589b47661cf24aebb6eb243cf0203010001a000300d06092a864886f70d010105050003820101004554987d17913f5925556ff2c7e89218971e8ebcdbb4ea259f4504085fde0c6bde590dfa237460e212804240a9463965edb9d7276f7d67fe7a661c119eb8c047c2d8ffe9579c553f089ea1fc5a3c0b8d9d7f0cdd2b7e86612e64d646cc1e20215db72c8fa2f8d310a073f93ac290c86c4fe57b3ee898d6d4728e6d41dbd79c729b96e2d0ee0bd29828ff3cda2d354e1dbc19250f6e10d027a1c55e90c74e8d783b8c826b1f0eab7a360ee5903ad435510c5b24774491cfda060b9b7d317f7bea84181b6f67d334023205dc8ec7dd172f3a385ac21bde094316b0d4d8b1876ff3e5b4b8bf4dbeb761a3e7e1bdacb906d1616d02789d86011aa1eb155db5a50e5f`

var pkcs10CSRAttrHex = `308202a130820189020100302b3129302706035504030c2064657631332e696e7465726e616c2e63616c6c6576612e756b706c632e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c0b3200a7027c4a5f48049b9afe3ba9f95fe2bd483bdd67505d96503177a2702727077f91037d27f31a1697f4eeb2de092f477e95746f574adbcc45005e47dcf635ec66cf2870d518eb7fd0bb8693883421502ce3ef4a3304c820f12c192c0eba7eeac3f647303b1215dabb1da5976bc78c760dbe7ca4b31517b5be50b5ced4cf95ea144bec2cf6b2506a036cb9a1f901be7393b6b28af2017effb9a8bf9c5ff7a44dc46c99fbfa064b357b7b5314457488de483e794db785521de6d8c6fca28f3ed83c3648ef5ffa54f2f1b9fe87e708d214b20aa445125d6949243801fa27f821d7e10998dd60ff6fe001ea01c52074b49d59589b47661cf24aebb6eb243cf0203010001a031301306092a864886f70d01090231060c044154554b301a06092a864886f70d010907310d0c0b7375706572536563726574300d06092a864886f70d0101050500038201010060d8f8bf327add93c158a73d10776d96c18f203278d08c091de5cb8f32cd9ed90d0042040455e6a6f6ed4b999cbfa3d9f6608d65b2ef2283658dca4f34e702f8dc2d28b177bf28acd5075361c623a0e8d18a7feae81590e1fab54e3e5f58f385fa5b857225c228e009017010de72baadb5a74eb27eff804547569ce8a2058f7f5e601d63df218da81da5f257a1c1d2a7a0a75ddf1e6fa8b77f3751fb9bca242b6d7a89090fecec2a160a1080a049c58b207dd3cdb9b38decdcb0bd8b38bd446b9d7eeeb32f5437e70632c1b9197df569d296a09508afd91d55ff94eb9cd26dd993ef2ecb05cdfc395aa45d9d92c80f09a31eea4614f3c38168e0b40d2bf20e9c`

var indentSpaces = `    `

func printLine(indent int, format string, args ...interface{}) {
    for i := 0; i < indent; i ++ {
        fmt.Print(indentSpaces)
    }

    fmt.Printf(format, args...)
    fmt.Print("\n")
}

func printByteBlock(indent, width int, bytes []byte) {
    for i := 0; i <= len(bytes) / width; i++ {
        s := i * width
        e := s + width
        if e > len(bytes) {
            e = len(bytes)
        }
        if s == e {
            break
        }
        for n := 0; n < indent; n++ {
            fmt.Print(indentSpaces)
        }
        for _, b := range bytes[s:e] {
            fmt.Printf("%02x:", b)
        }
        fmt.Print("\n")
    }
}

func pubAlgoToString(algo x509.PublicKeyAlgorithm) string {
    switch algo {
    case x509.RSA:
        return "rsaEncryption"
    case x509.DSA:
        return "dsaEncryption"
    }
    return "unknownEncryption"
}

func sigAlgoToString(algo x509.SignatureAlgorithm) string {
    switch algo {
    case x509.MD2WithRSA:
        return "md2WithRSAEncryption"
    case x509.MD5WithRSA:
        return "md5WithRSAEncryption"
    case x509.SHA1WithRSA:
        return "sha1WithRSAEncryption"
    case x509.SHA256WithRSA:
        return "sha256WithRSAEncryption"
    case x509.SHA384WithRSA:
        return "sha384WithRSAEncryption"
    case x509.SHA512WithRSA:
        return "sha512WithRSAEncryption"
    case x509.DSAWithSHA1:
        return "sha1WithDSAEncryption"
    case x509.DSAWithSHA256:
        return "sha256WithDSAEncryption"
    }
    return "unknownAlgorithm"
}

func Test_ParsePKCS10(t *testing.T) {
    derBytes, _ := hex.DecodeString(pkcs10CSRHex)
    csr, err := ParsePKCS10CSR(derBytes)
    if err != nil {
        t.Errorf("failed to decode PKCS10 CSR: %s", err)
        return
    }

    derBytes, _ = hex.DecodeString(pkcs10PrivateKeyHex)
    privKey, err := x509.ParsePKCS1PrivateKey(derBytes)
    if err != nil {
        t.Errorf("failed to decode PKCS1 key: %s", err)
        return
    }

    pubRsaKey := csr.SubjectKey.(*rsa.PublicKey)
    if pubRsaKey.N.Cmp(privKey.PublicKey.N) != 0 {
        t.Error("public key in CSR does not match PKCS1 key")
        return
    }

    // openssl style dumping of the CSR
    //outputCsr(csr)
}

func Test_ParsePKCS10WithAttrs(t *testing.T) {
    derBytes, _ := hex.DecodeString(pkcs10CSRAttrHex)
    csr, err := ParsePKCS10CSR(derBytes)
    if err != nil {
        t.Errorf("failed to decode PKCS10 CSR: %s", err)
        return
    }

    derBytes, _ = hex.DecodeString(pkcs10PrivateKeyHex)
    privKey, err := x509.ParsePKCS1PrivateKey(derBytes)
    if err != nil {
        t.Errorf("failed to decode PKCS1 key: %s", err)
        return
    }

    pubRsaKey := csr.SubjectKey.(*rsa.PublicKey)
    if pubRsaKey.N.Cmp(privKey.PublicKey.N) != 0 {
        t.Error("public key in CSR does not match PKCS1 key")
        return
    }

    if csr.Attributes[0].Name != CsrAttrUnstructuredName {
        t.Error("first attribute has wrong name")
        return
    }

    if csr.Attributes[1].Name != CsrAttrChallengePassword {
        t.Error("second attribute has wrong name")
        return
    }
}

func Test_CreatePKCS10(t *testing.T) {
    derBytes, _ := hex.DecodeString(pkcs10PrivateKeyHex)
    privKey, err := x509.ParsePKCS1PrivateKey(derBytes)
    if err != nil {
        t.Errorf("failed to decode PKCS1 key: %s", err)
        return
    }

    // We aren't testing Fqdn here
    fqdn, err := Fqdn()
    if err != nil {
        fqdn = "localhost.localdomain"
    }

    csr := &CertificationRequest{Subject:pkix.Name{CommonName: fqdn}}

    derBytes, err = CreateCertificateRequest(rand.Reader, csr, &privKey.PublicKey, privKey)

    if _, err := ParsePKCS10CSR(derBytes); err != nil {
        t.Errorf("failed to decode PKCS10 CSR: %s", err)
        return
    }
    //pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
}

func outputCsr(csr *CertificationRequest) {
    printLine(0, "Certificate Request:")
    printLine(1, "Data:")
    printLine(2, "Version: %d", csr.Version)
    printLine(2, "Subject: CN=%s", csr.Subject.CommonName)
    printLine(2, "Subject Public Key Info:")
    printLine(3, "Public Key Alogorithm: %s", pubAlgoToString(csr.SubjectKeyAlgorithm))

    switch csr.SubjectKeyAlgorithm {
        case x509.RSA:
            rsaKey := csr.SubjectKey.(*rsa.PublicKey)
            printLine(4, "Public-Key: (%d bit)", rsaKey.N.BitLen())
            printLine(4, "Modulus:")
            printByteBlock(5, 15, rsaKey.N.Bytes())
            printLine(4, "Exponent: %d (%#x)", rsaKey.E, rsaKey.E)
        case x509.DSA:
            printLine(4, "Public-Key: Get a better one")
    }
    printLine(2, "Attributes:")
    printLine(3, "(not supported)")
    printLine(1, "Signature Algorithm: %s", sigAlgoToString(csr.SignatureAlgorithm))
    printByteBlock(2, 18, csr.Signature)
}
