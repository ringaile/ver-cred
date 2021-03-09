package main

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

func main() {

	publ, priv, _ := ed25519.GenerateKey(nil)

	keyPair := KeyPair{
		publicKey:  publ,
		privateKey: priv,
	}

	metadata := IssuerMetadata{
		context:          []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		id:               "did:example:abfe13f712120431c276e12ecab",
		typeOfCredential: []string{"VerifiableCredential", "GraduationCredential"},
		issuer:           "https://example.edu/issuers/565049",
		issuanceDate:     time.Now(),
	}

	claim := Claim{
		id:                  "did:example:ebfeb1f712ebc6f1c276e12ec21",
		graduatedUniversity: "Frankfurt University",
	}

	createdCredential := createCredential(keyPair, metadata, claim)

	//verify the credential
	fmt.Println(verifyCredential(keyPair.publicKey, createdCredential))

	//create keypair for presenter
	publPresenter, privPresenter, _ := ed25519.GenerateKey(nil)

	keyPairPresenter := KeyPair{
		publicKey:  publPresenter,
		privateKey: privPresenter,
	}

	metadataPresenter := PresenterMetadata{
		context:            []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		typeOfPresentation: []string{"VerifiablePresentation", "CredentialManagerPresentation"},
	}

	presentedCredential := createPresentation(keyPairPresenter, metadataPresenter, createdCredential)

	//verify presentation
	fmt.Println(verifyPresentation(keyPairPresenter.publicKey, presentedCredential))

}
