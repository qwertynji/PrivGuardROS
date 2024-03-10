// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileConverter {
    // Mapping to store file ID to CID
    mapping(uint256 => string) public fileIdToCid;
    mapping(uint256 => string) public fileIdToHash;
    mapping(uint256 => string) public userIdToAccess;
    mapping(uint256 => string) public userIdToSignature;

    // 存储 fileID:CID
    function storeFileIdToCid(uint256 fileId, string memory cid) public {
        fileIdToCid[fileId] = cid;
    }

    //存储 fileID:hash
    function storeFileIdToHash(uint256 fileId, string memory hash) public {
        fileIdToHash[fileId] = hash;
    }

    //存储 userID:access
    function storeUserIdToAccess(uint256 userId, string memory access) public {
        userIdToAccess[userId] = access;
    }

    //存储 userID:signature
    function storeUserIdToSignature(uint256 userId, string memory signature) public {
        userIdToSignature[userId] = signature;
    }


    //获得CID
    function getFileCid(uint256 fileId) public view returns (string memory) {
        return fileIdToCid[fileId];
    }

    //获得hash
    function getFileHash(uint256 fileId) public view returns (string memory) {
        return fileIdToHash[fileId];
    }

    //获得access
    function getUserAccess(uint256 userId) public view returns (string memory) {
        return userIdToAccess[userId];
    }

    //获得signature
    function getUserSignature(uint256 userId) public view returns (string memory) {
        return userIdToSignature[userId];
    }

}