package main

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

type KeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

type IssuerMetadata struct {
	context          []string
	id               string
	typeOfCredential []string
	issuer           string
	issuanceDate     time.Time
}

type PresenterMetadata struct {
	context            []string
	typeOfPresentation []string
}

type Claim struct {
	id                  string
	graduatedUniversity string
}

type Proof struct {
	typeOfProof string
	created     time.Time
	creator     ed25519.PublicKey
	signature   []byte
}

type Credential struct {
	context           []string
	id                string
	typeOfCredential  []string
	issuer            string
	issuanceDate      time.Time
	credentialSubject Claim
	proof             Proof
}

type Presentation struct {
	context           []string
	typeOfPresentaion []string
	credential        Credential
	proof             Proof
}

//create credential
func createCredential(keyPair KeyPair, metadata IssuerMetadata, claim Claim) Credential {
	//create credential
	credential := Credential{
		context:           metadata.context,
		id:                metadata.id,
		typeOfCredential:  metadata.typeOfCredential,
		issuer:            metadata.issuer,
		issuanceDate:      metadata.issuanceDate,
		credentialSubject: claim,
	}

	//create proof
	proof := Proof{
		typeOfProof: "ed25519",
		created:     time.Now(),
		creator:     keyPair.publicKey,
		signature:   ed25519.Sign(keyPair.privateKey, []byte(fmt.Sprintf("%v", credential))),
	}

	//add proof
	credential.proof = proof

	return credential
}

//verify credential
func verifyCredential(publicKey ed25519.PublicKey, credential Credential) bool {
	//verify if the public key is the same as in the credential
	if string(publicKey) != string(credential.proof.creator) {
		return false
	}
	proofObj := credential.proof
	credential.proof = Proof{}
	//verify signature
	return ed25519.Verify(publicKey, []byte(fmt.Sprintf("%v", credential)), proofObj.signature)
}

//create presentation
func createPresentation(keyPair KeyPair, metadata PresenterMetadata, credential Credential) Presentation {
	presentation := Presentation{
		context:           metadata.context,
		typeOfPresentaion: metadata.typeOfPresentation,
		credential:        credential,
	}

	//create proof
	proofOfPresentaton := Proof{
		typeOfProof: "ed25519",
		created:     time.Now(),
		creator:     keyPair.publicKey,
		signature:   ed25519.Sign(keyPair.privateKey, []byte(fmt.Sprintf("%v", presentation))),
	}

	presentation.proof = proofOfPresentaton

	return presentation

}

//verify presentation
func verifyPresentation(publicKey ed25519.PublicKey, presentation Presentation) bool {
	//verify if the public key is the same as in the credential
	if string(publicKey) != string(presentation.proof.creator) {
		return false
	}
	proofObj := presentation.proof
	presentation.proof = Proof{}
	//verify signature
	return ed25519.Verify(publicKey, []byte(fmt.Sprintf("%v", presentation)), proofObj.signature)
}
