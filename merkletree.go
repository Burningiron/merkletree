package merkletree

import (
	"crypto/sha256"
	"hash"
	"math"
)

type MerkletreeItem interface {
	Bytes() []byte
}

type Merkletree struct {
	height int
	tree   [][]byte
	hasher hash.Hash
	data   []MerkletreeItem
}

func New(hasher hash.Hash, data []MerkletreeItem) *Merkletree {

	mt := Merkletree{
		hasher: hasher,
		data:   data,
	}

	if len(data) < 1 {
		mt.tree = make([][]byte, 1)
		mt.height = 1
		return &mt
	}

	h := int(math.Ceil(math.Log2(float64(len(data))))) + 1

	mt.height = h

	mt.tree = make([][]byte, int(math.Pow(2, float64(h)))-1)

	return &mt
}

func NewSha256Tree(data []MerkletreeItem) *Merkletree {
	return New(sha256.New(), data)
}

func (mt *Merkletree) GetTreeData() [][]byte {
	return mt.tree
}

func (mt *Merkletree) SumTree() {
	//Deal with edge input
	if len(mt.data) < 1 {
		mt.hasher.Reset()
		mt.tree[0] = mt.hasher.Sum(nil)
		return
	}

	if len(mt.data) == 1 {
		mt.hasher.Reset()
		mt.hasher.Write(mt.data[0].Bytes())
		mt.tree[0] = mt.hasher.Sum(nil)
		return
	}

	//Fill the leaf node of tree

	tp := int(math.Pow(2, float64(mt.height-1)) - 1)
	tu := tp - 1

	for i := range mt.data {
		mt.hasher.Reset()
		mt.hasher.Write(mt.data[i].Bytes())

		mt.tree[tp] = mt.hasher.Sum(nil)
		tp++
	}

	for ; tp < len(mt.tree); tp++ {
		mt.tree[tp] = nil
	}

	for ; tu >= 0; tu-- {
		mt.hasher.Reset()
		mt.hasher.Write(mt.tree[tu*2+1])
		mt.hasher.Write(mt.tree[tu*2+2])

		mt.tree[tu] = mt.hasher.Sum(nil)
	}

	return
}

func (mt *Merkletree) GetRoot() []byte {
	return mt.tree[0]
}
