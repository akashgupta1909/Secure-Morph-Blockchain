// SPDX-License-Identifier: MIT

pragma solidity >=0.4.22 <=0.8.20;

import "truffle/Assert.sol";
import "../contracts/BlockStorage.sol";

contract TestBlockStorage {
    string private verifierEncryptedKey = "verifier_key";
    string private userName = "user_name";
    string private userEncryptedKey = "user_key";
    string private changedUserEncryptedKey = "changed_user_key";
    string private mutableDataHash = "mutable_data_hash";
    string private immutableDataHash = "immutable_data_hash";
    BlockStorage private blockStorage;

    function beforeEach() public {
        blockStorage = new BlockStorage(verifierEncryptedKey);
    }

    function testStoreVerificationData() public {
        bool success = blockStorage.storeVerificationData(
            userName,
            mutableDataHash,
            immutableDataHash,
            userEncryptedKey
        );

        Assert.isTrue(success, "Data should be stored successfully");
    }

    function testStoreVerificationUserVerify() public {
        blockStorage.storeVerificationData(
            userName,
            mutableDataHash,
            immutableDataHash,
            userEncryptedKey
        );

        bool success = blockStorage.verifyUserIdentity(
            userEncryptedKey,
            userName,
            mutableDataHash,
            immutableDataHash
        );

        Assert.isTrue(success, "User should be verified successfully");
    }

    function testDeleteVerificationData() public {
        blockStorage.storeVerificationData(
            userName,
            mutableDataHash,
            immutableDataHash,
            userEncryptedKey
        );

        bool success = blockStorage.deleteVerificationData(
            userEncryptedKey,
            userName
        );

        Assert.isTrue(success, "Data should be deleted successfully");

        bool verificationSuccess = blockStorage.verifyUserIdentity(
            userEncryptedKey,
            userName,
            mutableDataHash,
            immutableDataHash
        );

        Assert.isFalse(
            verificationSuccess,
            "User should not be verified successfully"
        );
    }

    function testChangeEncryptionKey() public {
        blockStorage.storeVerificationData(
            userName,
            mutableDataHash,
            immutableDataHash,
            userEncryptedKey
        );

        bool success = blockStorage.changeUserEncryptionKey(
            userEncryptedKey,
            changedUserEncryptedKey,
            userName
        );

        Assert.isFalse(
            success,
            "Encryption key should not be changed within one day or maximum changed should be 5 time"
        );
    }

    function testReduceChangeCount() public {
        blockStorage.storeVerificationData(
            userName,
            mutableDataHash,
            immutableDataHash,
            userEncryptedKey
        );

        bool success = blockStorage.reduceChangeCount(
            userEncryptedKey,
            userName,
            2
        );

        Assert.isTrue(success, "User Count is changed");
    }
}
