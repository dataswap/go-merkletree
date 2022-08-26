// MIT License
//
// Copyright (c) 2022 Tommy TIAN
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package merkletree

import (
	"crypto/sha256"
	"hash"
	"sync"

	sha256simd "github.com/minio/sha256-simd"
)

var (
	sha256Digest     = sha256.New()
	sha256SIMDDigest = sha256simd.New()
	sha256DigestPool = sync.Pool{
		New: func() interface{} {
			hash := sha256.New()
			return &hash
		},
	}
	sha256SIMDDigestPool = sync.Pool{
		New: func() interface{} {
			hash := sha256simd.New()
			return &hash
		},
	}
)

// defaultHashFunc is used when no user hash function is specified.
// It implements SHA256 hash function.
func defaultHashFunc(data []byte) ([]byte, error) {
	sha256Digest.Reset()
	_, err := sha256Digest.Write(data)
	if err != nil {
		return nil, err
	}
	return sha256Digest.Sum(nil), nil
}

// defaultHashFuncParal is used when no user hash function is specified.
// It implements SHA256 hash function.
func defaultHashFuncParal(data []byte) ([]byte, error) {
	digest := sha256DigestPool.Get().(*hash.Hash)
	defer sha256DigestPool.Put(digest)
	(*digest).Reset()
	_, err := (*digest).Write(data)
	if err != nil {
		return nil, err
	}
	return (*digest).Sum(nil), nil
}

func simdHashFunc(data []byte) ([]byte, error) {
	sha256SIMDDigest.Reset()
	_, err := sha256SIMDDigest.Write(data)
	if err != nil {
		return nil, err
	}
	return sha256SIMDDigest.Sum(nil), nil
}

func simdHashFuncParal(data []byte) ([]byte, error) {
	digest := sha256SIMDDigestPool.Get().(*hash.Hash)
	defer sha256SIMDDigestPool.Put(digest)
	(*digest).Reset()
	_, err := (*digest).Write(data)
	if err != nil {
		return nil, err
	}
	return (*digest).Sum(nil), nil
}
