// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VoiceProofRegistry {

    struct VoiceRecord {
        address submitter;
        bytes32 voiceHash;
        int64   latitude;
        int64   longitude;
        uint64  timestamp;
        uint64  blockTime;
        bool    revoked;
    }

    mapping(bytes32 => VoiceRecord) public records;
    mapping(bytes32 => bool)        public exists;
    mapping(address => bytes32[])   private _userRecords;

    event VoiceRecorded(bytes32 indexed voiceHash, address indexed submitter, uint64 blockTime);
    event VoiceRevoked (bytes32 indexed voiceHash, address indexed submitter);

    function record(
        bytes32 voiceHash,
        uint64  timestamp,
        int64   latitude,
        int64   longitude
    ) external {
        require(!exists[voiceHash], "already recorded");
        require(
            uint64(block.timestamp) >= timestamp &&
            uint64(block.timestamp) - timestamp <= 3600,
            "timestamp out of range"
        );

        records[voiceHash] = VoiceRecord({
            submitter: msg.sender,
            voiceHash: voiceHash,
            latitude:  latitude,
            longitude: longitude,
            timestamp: timestamp,
            blockTime: uint64(block.timestamp),
            revoked:   false
        });
        exists[voiceHash] = true;
        _userRecords[msg.sender].push(voiceHash);

        emit VoiceRecorded(voiceHash, msg.sender, uint64(block.timestamp));
    }

    function revoke(bytes32 voiceHash) external {
        require(records[voiceHash].submitter == msg.sender, "not submitter");
        require(!records[voiceHash].revoked, "already revoked");
        records[voiceHash].revoked = true;
        emit VoiceRevoked(voiceHash, msg.sender);
    }

    function verify(bytes32 voiceHash)
        external view
        returns (bool valid, address submitter, uint64 blockTime)
    {
        if (!exists[voiceHash]) return (false, address(0), 0);
        VoiceRecord storage r = records[voiceHash];
        return (!r.revoked, r.submitter, r.blockTime);
    }

    function getUserRecords(address user) external view returns (bytes32[] memory) {
        return _userRecords[user];
    }
}
