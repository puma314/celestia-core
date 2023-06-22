package types

import (
	"bytes"
	"encoding/binary"
	"log"
	"math"
	"testing"

	"github.com/tendermint/tendermint/crypto/tmhash"
)

func TestSSZ(t *testing.T) {
	vset := randValidatorSet(10)
	ssz := vset.SSZ()
	log.Printf("SSZ serialization %v", ssz)
}

func ConstraintValBytes(valBytes []byte, pubkey []byte, vp int64) {
	// validator bytes = pubkey + voting power
	// [10, 34, 10, 32, pubkeybytes, 0x10, ]
	// prove bytes 4 through 36 are the same as the pubkey bytes
	// prove bits 37 through 45 are the same as the voting power bytes
	// except here skip the first bit of each chunk

	// In short:
	// [10, 34, 10, 32, pubkeybytes, 0x10, ...serialization of vp]

	computedVotingPower := 0
	pow := 0
	for i := 4 + 32 + 1; i < len(valBytes); i++ {
		b := valBytes[i]
		bbyte := int(uint8(b & 0x7f))
		computedVotingPower += int(math.Pow(2, float64(7*pow))) * bbyte
		pow++
	}
	if int64(computedVotingPower) != vp {
		panic("Computed voting power not equal to real vp")
	}

	if valBytes[0] != 0xa {
		panic("ValBytes[0] is not 0xa")
	}
	if valBytes[1] != 34 {
		panic("ValBytes[1] is not 34")
	}
	if valBytes[2] != 10 {
		panic("ValBytes[2] is not 10")
	}
	if valBytes[3] != 32 {
		panic("ValBytes[3] is not 32")
	}
	for i := 4; i < 4+32; i++ {
		b := valBytes[i]
		if b != pubkey[i-4] {
			panic("valbytes and pubkey check is off")
		}
	}
	if valBytes[4+32] != 0x10 {
		panic("ValBytes[36] is not 16")
	}
}

func VerifySigOrDummy(sigOrDummy []byte, blockHeader []byte, pubkey []byte) int64 {
	if len(sigOrDummy) == 0 {
		return 0
	} else {
		// verify_eddsa(sigOrDummy, blockHeader, pubkey)
		return 1
	}
}

func ConstraintValHash(valBytesArr [][]byte, valHash []byte) {
	// do merkle tree with leaf forwarding
	// have to account for true leaves or not
}

// From merkle package
var (
	leafPrefix  = []byte{0}
	innerPrefix = []byte{1}
)

func VerifyValBytesAgainstHash(valBytes []byte, valHash []byte, proof [][]byte, proofIndices []bool) {
	// Should be max 7 hashes
	leaf := tmhash.Sum(append(leafPrefix, valBytes...))
	for i := range proof {
		// If proof[i] is a dummy, then break
		if len(proof[i]) == 0 {
			break
		}
		var appended []byte
		if proofIndices[i] == true {
			appended = append(leaf, proof[i]...)
		} else {
			appended = append(proof[i], leaf...)
		}
		leaf = tmhash.Sum(append(innerPrefix, appended...))
	}
	if !bytes.Equal(leaf, valHash) {
		panic("recovered root is not equal to val hash")
	}
}

// Useful resources:
// https://github.com/celestiaorg/celestia-app/compare/main...evan-forbes:celestia-app:evan/ssz-valset
// In particular for getting proofs against fields in the header

func TestCopy(t *testing.T) {
	vset := randValidatorSet(10)
	log.Printf("Validator Set: %v", vset)
	log.Printf("Validator[0] Pubkey: %v", vset.Validators[0].PubKey)
	log.Printf("Validator[0] Pubkey Bytes: %v", vset.Validators[0].PubKey.Bytes())
	log.Printf("Validator[0] Voting Power: %v %x", vset.Validators[0].VotingPower, vset.Validators[0].VotingPower)
	// convert int64 to []byte
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutVarint(buf, vset.Validators[0].VotingPower)
	log.Printf("Validator[0] Voting Power ([]byte): %v", buf)

	by := vset.Validators[0].Bytes()
	log.Printf("Validator[0].Bytes(): %v", by)

	// public input: []validator_bytes
	// public_input: []validator_pubkey
	// public_input: []validator_voting_power
	// public_input: block_header
	// public_input: []signatures_or_dummy
	// public_input: validators_hash (from previous block)
	// output: next_validators_hash, next_validators_hash_proof
	// output: data_root, data_root_proof

	SignaturesOrDummy := make([][]byte, len(vset.Validators)) // # of validators signatures or dummy
	BlockHeader := make([]byte, 0)
	ValHash := make([]byte, 0)
	ValBytesProofs := make([][][]byte, len(vset.Validators))
	ProofIndices := make([][]bool, len(vset.Validators))
	SignedVp := 0
	TotalVp := 0
	for i := range vset.Validators {
		ConstraintValBytes(vset.Validators[i].Bytes(), vset.Validators[i].PubKey.Bytes(), vset.Validators[i].VotingPower)
		SigTrue := VerifySigOrDummy(SignaturesOrDummy[i], BlockHeader, vset.Validators[i].PubKey.Bytes())
		SignedVp += int(SigTrue) * int(vset.Validators[i].VotingPower)
		TotalVp += int(vset.Validators[i].VotingPower)
		// TODO: one option for verifying val_bytes
		VerifyValBytesAgainstHash(vset.Validators[i].Bytes(), ValHash, ValBytesProofs[i], ProofIndices[i])
	}

	// TODO: alternative option for verifying val_bytes
	AllValBytes := make([][]byte, len(vset.Validators))
	for i := range vset.Validators {
		AllValBytes[i] = vset.Validators[i].Bytes()
	}
	ConstraintValHash(AllValBytes, ValHash)

	// TODO: constraint that SignedVp >= 2/3 * TotalVp
	// ConstraintGeTwoThirds(signed_vp, total_vp)
	// TODO: verify merkle proofs for data_root, next_validators_hash against block_header
	// should be similar to VerifyValBytesAgainstHash
	// VerifyMerkleProof(next_validators_hash, block_header)
	// VerifyMerkleProof(data_root, block_header)

	vsetHash := vset.Hash()
	if len(vsetHash) == 0 {
		t.Fatalf("ValidatorSet had unexpected zero hash")
	}
}
