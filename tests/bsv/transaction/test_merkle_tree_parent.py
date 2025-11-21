"""
MerkleTreeParentテスト
GO SDKのmerkletreeparent_test.goを参考に実装
"""
import pytest
from bsv.merkle_tree_parent import merkle_tree_parent_str, merkle_tree_parent_bytes


def test_get_merkle_tree_parent_str():
    """Test GetMerkleTreeParentStr (GO: TestGetMerkleTreeParentStr)"""
    left_node = "d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231"
    right_node = "b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98"
    
    expected = "b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be"
    
    parent = merkle_tree_parent_str(left_node, right_node)
    assert parent == expected


def test_get_merkle_tree_parent():
    """Test GetMerkleTreeParent (GO: TestGetMerkleTreeParent)"""
    left_node = bytes.fromhex("d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231")
    right_node = bytes.fromhex("b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98")
    
    expected = bytes.fromhex("b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be")
    
    parent = merkle_tree_parent_bytes(left_node, right_node)
    assert parent == expected

