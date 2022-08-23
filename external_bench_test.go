package merkletree

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"runtime"
	"testing"

	mt "github.com/cbergoon/merkletree"
)

func BenchmarkMerkleTreeProofGen(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(nil, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeProofGenParallel(b *testing.B) {
	config := &Config{
		RunInParallel: true,
		NumRoutines:   runtime.NumCPU(),
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func (m mockDataBlock) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(m.data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (m mockDataBlock) Equals(other mt.Content) (bool, error) {
	return bytes.Equal(m.data, other.(mockDataBlock).data), nil
}

func generateCberTestCases(size int) []mt.Content {
	var contents []mt.Content
	for i := 0; i < size; i++ {
		contents = append(contents, mockDataBlock{
			data: make([]byte, 100),
		})
		_, err := rand.Read(contents[i].(mockDataBlock).data)
		if err != nil {
			panic(err)
		}
	}
	return contents
}

func Benchmark_cbergoonMerkleTreeProofGen(b *testing.B) {
	contents := generateCberTestCases(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree, err := mt.NewTree(contents)
		for j := 0; j < benchSize; j++ {
			_, _, err := tree.GetMerklePath(contents[j])
			if err != nil {
				b.Errorf("GetMerklePath() error = %v", err)
			}
		}
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeVerify(b *testing.B) {
	tree, blocks, err := verifySetup(benchSize)
	if err != nil {
		b.Errorf("setupFunc() error = %v", err)
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for idx := 0; idx < benchSize; idx++ {
			_, err := tree.Verify(blocks[10], tree.Proofs[10])
			if err != nil {
				b.Errorf("Verify() error = %v", err)
				return
			}
		}
	}
}

func Benchmark_cbergoonMerkleTreeVerify(b *testing.B) {
	contents := generateCberTestCases(benchSize)
	tree, err := mt.NewTree(contents)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for idx := 0; idx < benchSize; idx++ {
			_, err := tree.VerifyContent(contents[idx])
			if err != nil {
				b.Errorf("Verify() error = %v", err)
			}
		}
	}
}
