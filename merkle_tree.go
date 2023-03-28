package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Read the transaction hashes from file
	hashes, err := readTransactionHashesFromFile("transactions.txt")
	if err != nil {
		log.Fatal(err)
	}

	// Compute the Merkle tree root
	root := computeMerkleTreeRoot(hashes)

	// Output the root hash
	fmt.Println("Merkle tree root:", hex.EncodeToString(root[:]))
}

func readTransactionHashesFromFile(filename string) ([][32]byte, error) {
	// Read the file contents
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Parse each line as a transaction hash
	var hashes [][32]byte
	for _, line := range splitLines(content) {
		hash, err := hex.DecodeString(string(line))
		if err != nil {
			return nil, err
		}
		var hashArray [32]byte
		copy(hashArray[:], hash)
		hashes = append(hashes, hashArray)
	}

	return hashes, nil
}

func splitLines(data []byte) [][]byte {
	// Split data into lines
	var lines [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

func computeMerkleTreeRoot(hashes [][32]byte) [32]byte {
	// If there are no hashes, return the zero hash
	if len(hashes) == 0 {
		return sha256.Sum256(nil)
	}

	// Keep computing parent hashes until there is only one hash left
	for len(hashes) > 1 {
		var parentHashes [][32]byte

		// Compute the parent hash of each pair of hashes
		for i := 0; i < len(hashes); i += 2 {
			hash1 := hashes[i]
			var hash2 [32]byte
			if i+1 < len(hashes) {
				hash2 = hashes[i+1]
			}
			parentHash := sha256.Sum256(append(hash1[:], hash2[:]...))
			parentHashes = append(parentHashes, parentHash)
		}

		hashes = parentHashes
	}

	return hashes[0]
}
