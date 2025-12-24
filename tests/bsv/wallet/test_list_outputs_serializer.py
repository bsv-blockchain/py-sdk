"""
Comprehensive tests for bsv/wallet/serializer/list_outputs.py

Tests serialization and deserialization of list_outputs arguments and results.
"""

import pytest
from bsv.wallet.serializer.list_outputs import (
    serialize_list_outputs_args,
    deserialize_list_outputs_args,
    serialize_list_outputs_result,
    deserialize_list_outputs_result,
)


class TestSerializeListOutputsArgs:
    """Test serialize_list_outputs_args() function."""
    
    def test_serialize_minimal_args(self):
        """Test serializing minimal (empty) arguments."""
        args = {}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_serialize_with_basket(self):
        """Test serializing with basket parameter."""
        args = {"basket": "default"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b"default" in result
    
    def test_serialize_with_empty_basket(self):
        """Test serializing with empty basket."""
        args = {"basket": ""}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_single_tag(self):
        """Test serializing with single tag."""
        args = {"tags": ["tag1"]}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b"tag1" in result
    
    def test_serialize_with_multiple_tags(self):
        """Test serializing with multiple tags."""
        args = {"tags": ["tag1", "tag2", "tag3"]}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b"tag1" in result
        assert b"tag2" in result
        assert b"tag3" in result
    
    def test_serialize_with_empty_tags_list(self):
        """Test serializing with empty tags list."""
        args = {"tags": []}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_no_tags(self):
        """Test serializing without tags (None)."""
        args = {"tags": None}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_tag_query_mode_all(self):
        """Test serializing with tagQueryMode='all'."""
        args = {"tagQueryMode": "all"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b'\x01' in result  # Mode "all" = 1
    
    def test_serialize_tag_query_mode_any(self):
        """Test serializing with tagQueryMode='any'."""
        args = {"tagQueryMode": "any"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b'\x02' in result  # Mode "any" = 2
    
    def test_serialize_tag_query_mode_invalid(self):
        """Test serializing with invalid tagQueryMode."""
        args = {"tagQueryMode": "invalid"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b'\xff' in result  # Invalid mode = -1
    
    def test_serialize_include_locking_scripts(self):
        """Test serializing with include='locking scripts'."""
        args = {"include": "locking scripts"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_entire_transactions(self):
        """Test serializing with include='entire transactions'."""
        args = {"include": "entire transactions"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_invalid(self):
        """Test serializing with invalid include value."""
        args = {"include": "invalid"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_custom_instructions_true(self):
        """Test serializing with includeCustomInstructions=True."""
        args = {"includeCustomInstructions": True}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_custom_instructions_false(self):
        """Test serializing with includeCustomInstructions=False."""
        args = {"includeCustomInstructions": False}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_custom_instructions_none(self):
        """Test serializing with includeCustomInstructions=None."""
        args = {"includeCustomInstructions": None}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_tags_true(self):
        """Test serializing with includeTags=True."""
        args = {"includeTags": True}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_tags_false(self):
        """Test serializing with includeTags=False."""
        args = {"includeTags": False}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_labels_true(self):
        """Test serializing with includeLabels=True."""
        args = {"includeLabels": True}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_include_labels_false(self):
        """Test serializing with includeLabels=False."""
        args = {"includeLabels": False}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_limit(self):
        """Test serializing with limit parameter."""
        args = {"limit": 10}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_offset(self):
        """Test serializing with offset parameter."""
        args = {"offset": 5}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_limit_and_offset(self):
        """Test serializing with both limit and offset."""
        args = {"limit": 100, "offset": 50}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_seek_permission_true(self):
        """Test serializing with seekPermission=True."""
        args = {"seekPermission": True}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_seek_permission_false(self):
        """Test serializing with seekPermission=False."""
        args = {"seekPermission": False}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_seek_permission_none(self):
        """Test serializing with seekPermission=None."""
        args = {"seekPermission": None}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_all_options(self):
        """Test serializing with all optional parameters."""
        args = {
            "basket": "custom",
            "tags": ["tag1", "tag2"],
            "tagQueryMode": "all",
            "include": "locking scripts",
            "includeCustomInstructions": True,
            "includeTags": True,
            "includeLabels": False,
            "limit": 100,
            "offset": 10,
            "seekPermission": True
        }
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 20


class TestDeserializeListOutputsArgs:
    """Test deserialize_list_outputs_args() function."""
    
    def test_deserialize_minimal(self):
        """Test deserializing minimal arguments."""
        args = {}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert isinstance(deserialized, dict)
        assert "basket" in deserialized
        assert "tags" in deserialized
    
    def test_deserialize_with_basket(self):
        """Test deserializing with basket."""
        args = {"basket": "test_basket"}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["basket"] == "test_basket"
    
    def test_deserialize_with_tags(self):
        """Test deserializing with tags."""
        args = {"tags": ["tag1", "tag2"]}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["tags"] == ["tag1", "tag2"]
    
    def test_deserialize_tag_query_mode_all(self):
        """Test deserializing tagQueryMode='all'."""
        args = {"tagQueryMode": "all"}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["tagQueryMode"] == "all"
    
    def test_deserialize_tag_query_mode_any(self):
        """Test deserializing tagQueryMode='any'."""
        args = {"tagQueryMode": "any"}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["tagQueryMode"] == "any"
    
    def test_deserialize_include_locking_scripts(self):
        """Test deserializing include='locking scripts'."""
        args = {"include": "locking scripts"}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["include"] == "locking scripts"
    
    def test_deserialize_include_entire_transactions(self):
        """Test deserializing include='entire transactions'."""
        args = {"include": "entire transactions"}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["include"] == "entire transactions"
    
    def test_deserialize_boolean_options(self):
        """Test deserializing boolean options."""
        args = {
            "includeCustomInstructions": True,
            "includeTags": False,
            "includeLabels": True
        }
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["includeCustomInstructions"] is True
        assert deserialized["includeTags"] is False
        assert deserialized["includeLabels"] is True
    
    def test_deserialize_none_options(self):
        """Test deserializing None options."""
        args = {
            "includeCustomInstructions": None,
            "includeTags": None,
            "includeLabels": None
        }
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["includeCustomInstructions"] is None
        assert deserialized["includeTags"] is None
        assert deserialized["includeLabels"] is None
    
    def test_deserialize_limit_and_offset(self):
        """Test deserializing limit and offset."""
        args = {"limit": 50, "offset": 25}
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        assert deserialized["limit"] == 50
        assert deserialized["offset"] == 25


class TestArgsRoundTrip:
    """Test round-trip serialization/deserialization of arguments."""
    
    @pytest.mark.parametrize("args", [
        {},
        {"basket": "default"},
        {"tags": ["tag1"]},
        {"tags": ["tag1", "tag2", "tag3"]},
        {"tagQueryMode": "all"},
        {"tagQueryMode": "any"},
        {"include": "locking scripts"},
        {"include": "entire transactions"},
        {"limit": 10},
        {"offset": 5},
        {"limit": 100, "offset": 50},
        {"includeCustomInstructions": True},
        {"includeTags": False},
        {"includeLabels": True},
        {"seekPermission": True},
        {"seekPermission": False},
    ])
    def test_args_round_trip(self, args):
        """Test that args can be serialized and deserialized correctly."""
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        
        # Check each field that was set
        for key, value in args.items():
            assert key in deserialized
            assert deserialized[key] == value
    
    def test_complex_args_round_trip(self):
        """Test round trip with all parameters."""
        args = {
            "basket": "complex",
            "tags": ["tag1", "tag2", "tag3"],
            "tagQueryMode": "all",
            "include": "entire transactions",
            "includeCustomInstructions": True,
            "includeTags": False,
            "includeLabels": True,
            "limit": 100,
            "offset": 50,
            "seekPermission": True
        }
        serialized = serialize_list_outputs_args(args)
        deserialized = deserialize_list_outputs_args(serialized)
        
        assert deserialized["basket"] == args["basket"]
        assert deserialized["tags"] == args["tags"]
        assert deserialized["tagQueryMode"] == args["tagQueryMode"]
        assert deserialized["include"] == args["include"]
        assert deserialized["includeCustomInstructions"] == args["includeCustomInstructions"]
        assert deserialized["includeTags"] == args["includeTags"]
        assert deserialized["includeLabels"] == args["includeLabels"]
        assert deserialized["limit"] == args["limit"]
        assert deserialized["offset"] == args["offset"]
        assert deserialized["seekPermission"] == args["seekPermission"]


class TestSerializeListOutputsResult:
    """Test serialize_list_outputs_result() function."""
    
    def test_serialize_empty_outputs(self):
        """Test serializing empty outputs list."""
        result = {"outputs": []}
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
    
    def test_serialize_single_output(self):
        """Test serializing single output."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "lockingScript": b"\x76\xa9\x14",
                "customInstructions": "test",
                "tags": ["tag1"],
                "labels": ["label1"]
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
        assert len(serialized) > 32  # At least txid size
    
    def test_serialize_multiple_outputs(self):
        """Test serializing multiple outputs."""
        result = {
            "outputs": [
                {
                    "outpoint": {"txid": b"\x01" * 32, "index": 0},
                    "satoshis": 1000,
                },
                {
                    "outpoint": {"txid": b"\x02" * 32, "index": 1},
                    "satoshis": 2000,
                }
            ]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
        assert len(serialized) > 64  # At least 2 txids
    
    def test_serialize_with_beef(self):
        """Test serializing with BEEF data."""
        result = {
            "beef": b"beef_data_here",
            "outputs": []
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
        assert b"beef_data_here" in serialized
    
    def test_serialize_without_beef(self):
        """Test serializing without BEEF data."""
        result = {"outputs": []}
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
    
    def test_serialize_output_without_locking_script(self):
        """Test serializing output without locking script."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "lockingScript": None
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
    
    def test_serialize_output_empty_locking_script(self):
        """Test serializing output with empty locking script."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "lockingScript": b""
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
    
    def test_serialize_output_without_custom_instructions(self):
        """Test serializing output without custom instructions."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "customInstructions": None
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
    
    def test_serialize_output_empty_custom_instructions(self):
        """Test serializing output with empty custom instructions."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "customInstructions": ""
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
    
    def test_serialize_output_with_tags_and_labels(self):
        """Test serializing output with tags and labels."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "tags": ["tag1", "tag2", "tag3"],
                "labels": ["label1", "label2"]
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)
        assert b"tag1" in serialized
        assert b"label1" in serialized
    
    def test_serialize_output_empty_tags_and_labels(self):
        """Test serializing output with empty tags and labels."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x00" * 32, "index": 0},
                "satoshis": 1000,
                "tags": [],
                "labels": []
            }]
        }
        serialized = serialize_list_outputs_result(result)
        assert isinstance(serialized, bytes)


class TestDeserializeListOutputsResult:
    """Test deserialize_list_outputs_result() function."""
    
    def test_deserialize_empty_outputs(self):
        """Test deserializing empty outputs."""
        result = {"outputs": []}
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert "totalOutputs" in deserialized
        assert deserialized["totalOutputs"] == 0
        assert deserialized["outputs"] == []
    
    def test_deserialize_single_output(self):
        """Test deserializing single output."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\x12" * 32, "index": 5},
                "satoshis": 1000,
                "lockingScript": b"\x76\xa9",
                "customInstructions": "test",
                "tags": ["tag1"],
                "labels": ["label1"]
            }]
        }
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert deserialized["totalOutputs"] == 1
        assert len(deserialized["outputs"]) == 1
        output = deserialized["outputs"][0]
        assert output["outpoint"]["txid"] == b"\x12" * 32
        assert output["outpoint"]["index"] == 5
        assert output["satoshis"] == 1000
        assert output["tags"] == ["tag1"]
        assert output["labels"] == ["label1"]
    
    def test_deserialize_with_beef(self):
        """Test deserializing with BEEF data."""
        result = {
            "beef": b"test_beef",
            "outputs": []
        }
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert "beef" in deserialized
        assert deserialized["beef"] == b"test_beef"
    
    def test_deserialize_without_beef(self):
        """Test deserializing without BEEF data."""
        result = {"outputs": []}
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        # beef should not be in result when not provided
        assert "beef" not in deserialized or deserialized.get("beef") is None


class TestResultRoundTrip:
    """Test round-trip serialization/deserialization of results."""
    
    def test_empty_result_round_trip(self):
        """Test round trip with empty result."""
        result = {"outputs": []}
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert deserialized["totalOutputs"] == 0
        assert deserialized["outputs"] == []
    
    def test_single_output_round_trip(self):
        """Test round trip with single output."""
        result = {
            "outputs": [{
                "outpoint": {"txid": b"\xAB" * 32, "index": 3},
                "satoshis": 5000,
                "lockingScript": b"\x76\xa9\x14\x00" * 5,
                "customInstructions": "custom",
                "tags": ["tag1", "tag2"],
                "labels": ["label1"]
            }]
        }
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert deserialized["totalOutputs"] == 1
        output = deserialized["outputs"][0]
        assert output["outpoint"]["txid"] == b"\xAB" * 32
        assert output["outpoint"]["index"] == 3
        assert output["satoshis"] == 5000
        assert len(output["lockingScript"]) > 0
        assert output["tags"] == ["tag1", "tag2"]
        assert output["labels"] == ["label1"]
    
    def test_multiple_outputs_round_trip(self):
        """Test round trip with multiple outputs."""
        result = {
            "outputs": [
                {
                    "outpoint": {"txid": b"\x01" * 32, "index": 0},
                    "satoshis": 1000,
                    "tags": ["tag1"],
                    "labels": []
                },
                {
                    "outpoint": {"txid": b"\x02" * 32, "index": 1},
                    "satoshis": 2000,
                    "tags": [],
                    "labels": ["label1"]
                },
                {
                    "outpoint": {"txid": b"\x03" * 32, "index": 2},
                    "satoshis": 3000,
                    "tags": ["tag2", "tag3"],
                    "labels": ["label2", "label3"]
                }
            ]
        }
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert deserialized["totalOutputs"] == 3
        assert len(deserialized["outputs"]) == 3
        
        for i, output in enumerate(deserialized["outputs"]):
            expected_txid = bytes([i + 1] * 32)
            assert output["outpoint"]["txid"] == expected_txid
            assert output["outpoint"]["index"] == i
            assert output["satoshis"] == (i + 1) * 1000
    
    def test_with_beef_round_trip(self):
        """Test round trip with BEEF data."""
        result = {
            "beef": b"sample_beef_data",
            "outputs": [{
                "outpoint": {"txid": b"\xFF" * 32, "index": 0},
                "satoshis": 100,
                "tags": [],
                "labels": []
            }]
        }
        serialized = serialize_list_outputs_result(result)
        deserialized = deserialize_list_outputs_result(serialized)
        
        assert "beef" in deserialized
        assert deserialized["beef"] == b"sample_beef_data"
        assert deserialized["totalOutputs"] == 1

