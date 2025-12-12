from abc import ABC, abstractmethod


class ChainTracker(ABC):
    """
    The Chain Tracker is responsible for verifying the validity of a given Merkle root
    for a specific block height within the blockchain.

    Chain Trackers ensure the integrity of the blockchain by
    validating new headers against the chain's history. They use accumulated
    proof-of-work and protocol adherence as metrics to assess the legitimacy of blocks.
    """

    @abstractmethod
    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        """
        Verify the validity of a Merkle root for a given block height.

        :param root: The Merkle root to verify.
        :param height: The block height to verify against.
        :return: A boolean indicating if the Merkle root is valid for the specified block height.
        """
        pass

    @abstractmethod
    async def current_height(self) -> int:
        """
        Get the current height of the blockchain.
        
        This method corresponds to TypeScript's currentHeight() in ChainTracker.
        
        Reference: sdk/ts-sdk/src/transaction/ChainTracker.ts
        
        :return: The current blockchain height as a positive integer.
        :raises: Exception if unable to retrieve height from the blockchain.
        """
        pass
