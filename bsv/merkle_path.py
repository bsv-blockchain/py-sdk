from typing import List, Optional, TypedDict

from .chaintracker import ChainTracker
from .hash import hash256
from .utils import Reader, Writer, to_bytes, to_hex


class MerkleLeaf(TypedDict, total=False):
    offset: int
    hash_str: Optional[str]
    txid: Optional[bool]
    duplicate: Optional[bool]


class MerklePath:
    """
    Represents a Merkle Path, which is used to provide a compact proof of inclusion for a
    transaction in a block. This class encapsulates all the details required for creating
    and verifying Merkle Proofs.

    Attributes:
        block_height (int): The height of the block in which the transaction is included.
        path (List[List[MerkleLeaf]]): A tree structure representing the Merkle Path,
            with each level containing information about the nodes involved in constructing the proof.

    Example:
        # Creating and verifying a Merkle Path
        merkle_path = MerklePath.from_hex('...')
        is_valid = await merkle_path.verify(txid, chain_tracker)

    Description:
        The MerklePath class is useful for verifying transactions in a lightweight and efficient manner without
        needing the entire block data. This class offers functionalities for creating, converting,
        and verifying these proofs.
    """

    def __init__(self, block_height: int, path: list[list[MerkleLeaf]]):
        self.block_height = block_height
        self.path = path

        self._validate_path_structure()
        self._validate_root_consistency()

    def _validate_path_structure(self) -> None:
        """Validate the structure and offsets of the Merkle path."""
        legal_offsets = [set() for _ in range(len(self.path))]

        for height, leaves in enumerate(self.path):
            self._validate_level_not_empty(height, leaves)
            self._validate_level_offsets(height, leaves, legal_offsets)

    def _validate_level_not_empty(self, height: int, leaves: list[MerkleLeaf]) -> None:
        """Validate that level 0 is not empty."""
        if not leaves and height == 0:
            raise ValueError(f"Empty level at height: {height}")

    def _validate_level_offsets(self, height: int, leaves: list[MerkleLeaf], legal_offsets: list[set]) -> None:
        """Validate offsets for a single level."""
        offsets_at_this_height = set()

        for leaf in leaves:
            self._validate_unique_offset(leaf, height, offsets_at_this_height)
            self._validate_legal_offset(leaf, height, legal_offsets)
            self._update_legal_offsets_for_higher_levels(leaf, height, legal_offsets)

    def _validate_unique_offset(self, leaf: MerkleLeaf, height: int, offsets_at_height: set) -> None:
        """Validate that offset is unique within this level."""
        if leaf["offset"] in offsets_at_height:
            raise ValueError(f"Duplicate offset: {leaf['offset']}, at height: {height}")
        offsets_at_height.add(leaf["offset"])

    def _validate_legal_offset(self, leaf: MerkleLeaf, height: int, legal_offsets: list[set]) -> None:
        """Validate that offset is legal for this height."""
        if height > 0 and leaf["offset"] not in legal_offsets[height]:
            legal_offsets_at_height = ", ".join(map(str, legal_offsets[height]))
            raise ValueError(
                f"Invalid offset: {leaf['offset']}, at height: {height}, with legal offsets: {legal_offsets_at_height}"
            )

    def _update_legal_offsets_for_higher_levels(self, leaf: MerkleLeaf, height: int, legal_offsets: list[set]) -> None:
        """Update legal offsets for higher levels based on level 0 leaves."""
        if height == 0 and not leaf.get("duplicate"):
            for h in range(1, len(self.path)):
                legal_offsets[h].add(leaf["offset"] >> h ^ 1)

    def _validate_root_consistency(self) -> None:
        """Validate that all level 0 leaves produce the same root."""
        if not self.path or not self.path[0]:
            return

        root = None
        for leaf in self.path[0]:
            leaf_root = self.compute_root(leaf.get("hash_str"))
            if root is None:
                root = leaf_root
            elif root != leaf_root:
                raise ValueError("Mismatched roots")

    @staticmethod
    def from_hex(hex_str: str) -> "MerklePath":
        """
        Creates a MerklePath instance from a hexadecimal string.

        Args:
            hex_str (str): The hexadecimal string representation of the Merkle Path.

        Returns:
            MerklePath: A new MerklePath instance.
        """
        return MerklePath.from_binary(to_bytes(hex_str, "hex"))

    @staticmethod
    def from_reader(reader: Reader) -> "MerklePath":
        """
        Creates a MerklePath instance from a Reader object.

        Args:
            reader (Reader): The Reader object.

        Returns:
            MerklePath: A new MerklePath instance.
        """
        block_height = reader.read_var_int_num()
        tree_height = reader.read_uint8()
        path = [[] for _ in range(tree_height)]

        for level in range(tree_height):
            n_leaves_at_this_height = reader.read_var_int_num()
            while n_leaves_at_this_height:
                offset = reader.read_var_int_num()
                flags = reader.read_uint8()
                leaf = {"offset": offset}

                if flags & 1:
                    leaf["duplicate"] = True
                else:
                    if flags & 2:
                        leaf["txid"] = True
                    leaf["hash_str"] = to_hex(reader.read(32)[::-1])

                path[level].append(leaf)
                n_leaves_at_this_height -= 1

            path[level].sort(key=lambda e: e["offset"])

        return MerklePath(block_height, path)

    @staticmethod
    def from_binary(bump: bytes) -> "MerklePath":
        """
        Creates a MerklePath instance from a bytes object.

        Args:
            bump (bytes): The binary array representation of the Merkle Path.

        Returns:
            MerklePath: A new MerklePath instance.
        """
        reader = Reader(bump)
        return MerklePath.from_reader(reader)

    def to_binary(self) -> bytes:
        """
        Converts the MerklePath to a binary array format.

        Returns:
            bytes: The binary array representation of the Merkle Path.
        """
        writer = Writer()
        writer.write_var_int_num(self.block_height)
        tree_height = len(self.path)
        writer.write_uint8(tree_height)

        for level in range(tree_height):
            n_leaves = len(self.path[level])
            writer.write_var_int_num(n_leaves)

            for leaf in self.path[level]:
                writer.write_var_int_num(leaf["offset"])
                flags = 0
                if leaf.get("duplicate"):
                    flags |= 1
                if leaf.get("txid"):
                    flags |= 2
                writer.write_uint8(flags)

                if not (flags & 1):
                    writer.write(to_bytes(leaf["hash_str"], "hex")[::-1])

        return writer.to_bytes()

    def to_hex(self) -> str:
        """
        Converts the MerklePath to a hexadecimal string format.

        Returns:
            str: The hexadecimal string representation of the Merkle Path.
        """
        return to_hex(self.to_binary())

    def compute_root(self, txid: Optional[str] = None) -> str:
        """
        Computes the Merkle root from the provided transaction ID.

        Args:
            txid (Optional[str]): The transaction ID to compute the Merkle root for. If not provided,
                the root will be computed from an unspecified branch, and not all branches will be validated!

        Returns:
            str: The computed Merkle root as a hexadecimal string.

        Raises:
            ValueError: If the transaction ID is not part of the Merkle Path.
        """
        if not isinstance(txid, str):
            txid = next(leaf["hash_str"] for leaf in self.path[0] if leaf and "hash_str" in leaf)

        # Find the index of the txid at the lowest level of the Merkle tree
        try:
            index = next(leaf["offset"] for leaf in self.path[0] if leaf.get("hash_str") == txid)
        except StopIteration:
            raise ValueError(f"This proof does not contain the txid: {txid}")

        # Calculate the root using the index as a way to determine which direction to concatenate.
        def hash_fn(m: str) -> str:
            return to_hex(hash256(to_bytes(m, "hex")[::-1])[::-1])

        working_hash = txid
        for height in range(len(self.path)):
            offset = (index >> height) ^ 1
            leaf = self.find_or_compute_leaf(height, offset)
            if not isinstance(leaf, dict):
                raise ValueError(f"Missing hash for index {index} at height {height}")

            if leaf.get("duplicate"):
                working_hash = hash_fn(working_hash + working_hash)
            elif offset % 2 != 0:
                working_hash = hash_fn(leaf["hash_str"] + working_hash)
            else:
                working_hash = hash_fn(working_hash + leaf["hash_str"])

        return working_hash

    def find_or_compute_leaf(self, height: int, offset: int) -> Optional[MerkleLeaf]:
        def hash_fn(m: str) -> str:
            return to_hex(hash256(to_bytes(m, "hex")[::-1])[::-1])

        leaf = next((e for e in self.path[height] if e["offset"] == offset), None)
        if leaf:
            return leaf

        if height == 0:
            return None

        h = height - 1
        e = offset << 1

        leaf0 = self.find_or_compute_leaf(h, e)
        if not leaf0 or not leaf0.get("hash_str"):
            return None

        leaf1 = self.find_or_compute_leaf(h, e + 1)
        if not leaf1:
            return None

        if leaf1.get("duplicate"):
            working_hash = hash_fn(leaf0["hash_str"] + leaf0["hash_str"])
        else:
            working_hash = hash_fn(leaf1["hash_str"] + leaf0["hash_str"])

        return {"offset": offset, "hash_str": working_hash}

    async def verify(self, txid: str, chaintracker: ChainTracker) -> bool:
        """
        Verifies if the given transaction ID is part of the Merkle tree at the specified block height.

        Args:
            txid (str): The transaction ID to verify.
            chaintracker (ChainTracker): The ChainTracker instance used to verify the Merkle root.

        Returns:
            bool: True if the transaction ID is valid within the Merkle Path at the specified block height.
        """
        root = self.compute_root(txid)
        res = await chaintracker.is_valid_root_for_height(root, self.block_height)
        return res

    def combine(self, other: "MerklePath") -> None:
        """
        Combines this MerklePath with another to create a compound proof.

        Args:
            other (MerklePath): Another MerklePath to combine with this path.

        Raises:
            ValueError: If the paths have different block heights or roots.
        """
        if self.block_height != other.block_height:
            raise ValueError("You cannot combine paths which do not have the same block height.")

        root1 = self.compute_root()
        root2 = other.compute_root()
        if root1 != root2:
            raise ValueError("You cannot combine paths which do not have the same root.")

        combined_path = []
        for h in range(len(self.path)):
            combined_level = self.path[h] + [
                leaf for leaf in other.path[h] if leaf["offset"] not in {e["offset"] for e in self.path[h]}
            ]
            for leaf in other.path[h]:
                if "txid" in leaf:
                    for e in combined_level:
                        if e["offset"] == leaf["offset"]:
                            e["txid"] = True
            combined_path.append(combined_level)
        self.path = combined_path
        self.trim()

    def trim(self) -> None:
        """
        Remove all internal nodes that are not required by level zero txid nodes.
        Assumes that at least all required nodes are present.
        Leaves all levels sorted by increasing offset.
        """

        def push_if_new(v: int, a: list[int]) -> None:
            if not a or a[-1] != v:
                a.append(v)

        def drop_offsets_from_level(drop_offsets: list[int], level: int) -> None:
            for i in reversed(drop_offsets):
                idx = next((j for j, n in enumerate(self.path[level]) if n["offset"] == i), None)
                if idx is not None:
                    self.path[level].pop(idx)

        def next_computed_offsets(cos: list[int]) -> list[int]:
            ncos = []
            for o in cos:
                push_if_new(o >> 1, ncos)
            return ncos

        computed_offsets = []
        drop_offsets = []
        for h in range(len(self.path)):
            self.path[h].sort(key=lambda x: x["offset"])

        for e in self.path[0]:
            if e.get("txid"):
                push_if_new(e["offset"] >> 1, computed_offsets)
            else:
                is_odd = e["offset"] % 2 == 1
                peer = next((n for n in self.path[0] if n["offset"] == e["offset"] + (1 if is_odd else -1)), None)
                if peer and not peer.get("txid"):
                    push_if_new(peer["offset"], drop_offsets)

        drop_offsets_from_level(drop_offsets, 0)
        # print('testing', self.path)
        for h in range(1, len(self.path)):
            drop_offsets = computed_offsets
            computed_offsets = next_computed_offsets(computed_offsets)
            drop_offsets_from_level(drop_offsets, h)
