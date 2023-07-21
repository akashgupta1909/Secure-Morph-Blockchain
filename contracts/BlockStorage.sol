// SPDX-License-Identifier: MIT

/**
 * @title This contract is to store the hashed data in the form of key value pair
 * @author Akash Gupta
 * @notice This contract helps in verifying the user based on the encrypted key and hashed data
 */

pragma solidity >=0.4.22 <=0.8.20;

contract BlockStorage {
    struct StoredVerificationData {
        string userName; // User name of the user
        string mutableDataHash; // Chameleon hash of the mutable data
        string immutableDataHash; // Hash of the immutable data
        uint256 updatedAt; // Time at which the data is updated
        uint256 changeCount; // Number of times the data is modified
    }

    address verifierAddress; // Address of the verifier
    string verifierEncryptedKey; // Encrypted key of the verifier

    // Mapping of the user name and the stored verification data
    mapping(string => StoredVerificationData) storedVerificationData;

    // Multiple events to emit the function status
    event VerificationErrorMessage(string message);
    event VerificationDataStored(
        string userName,
        string mutableDataHash,
        string immutableDataHash,
        uint256 updatedAt,
        uint256 changeCount
    );
    event VerificationDataDeleted(string userName);
    event VerificationChangeEncryptionKey(
        string newEncryptionKey,
        string oldEncryptionKey,
        string userName
    );
    event VerificationChangeCountReduced(string userName, uint256 changeCount);

    /**
     * @dev This function intializes the verifier address
     * @param _verifierEncryptedKey Encrypted key of the verifier
     */
    constructor(string memory _verifierEncryptedKey) {
        verifierAddress = msg.sender;
        verifierEncryptedKey = _verifierEncryptedKey;
    }

    // Modifier to check if the sender is the verifier
    modifier onlyVerifier() {
        require(
            msg.sender == verifierAddress,
            "Only verifier has the access the required operation"
        );
        _;
    }

    /**
     * @dev This function is used to store the verification data of the user overloaded with _changeCount
     * @param _userName User name of the user
     * @param _mutableDataHash Chameleon hash of the mutable data
     * @param _immutableDataHash Hash of the immutable data
     * @param _userEncryptedKey Encrypted key of the user
     * @param _changeCount Number of times the data is modified
     * @return bool Returns true if the data is stored successfully
     */
    function storeVerificationData(
        string memory _userName,
        string memory _mutableDataHash,
        string memory _immutableDataHash,
        string memory _userEncryptedKey,
        uint256 _changeCount
    ) public onlyVerifier returns (bool) {
        string memory _encryptedKey = string(
            abi.encodePacked(_userEncryptedKey, verifierEncryptedKey, _userName)
        );

        StoredVerificationData
            memory _storedVerificationData = storedVerificationData[
                _encryptedKey
            ];
        if (
            keccak256(abi.encodePacked(_storedVerificationData.userName)) ==
            keccak256(abi.encodePacked(_userName))
        ) {
            emit VerificationErrorMessage(
                "User already exists, please change the userName"
            );
            return false;
        }

        storedVerificationData[_encryptedKey] = StoredVerificationData(
            _userName,
            _mutableDataHash,
            _immutableDataHash,
            block.timestamp,
            _changeCount
        );

        emit VerificationDataStored(
            _userName,
            _mutableDataHash,
            _immutableDataHash,
            block.timestamp,
            _changeCount
        );
        return true;
    }

    /**
     * @dev This function is used to store the verification data of the user
     * @param _userName User name of the user
     * @param _mutableDataHash Chameleon hash of the mutable data
     * @param _immutableDataHash Hash of the immutable data
     * @param _userEncryptedKey Encrypted key of the user
     * @return bool Returns true if the data is stored successfully
     */
    function storeVerificationData(
        string memory _userName,
        string memory _mutableDataHash,
        string memory _immutableDataHash,
        string memory _userEncryptedKey
    ) public onlyVerifier returns (bool) {
        string memory _encryptedKey = string(
            abi.encodePacked(_userEncryptedKey, verifierEncryptedKey, _userName)
        );

        StoredVerificationData
            memory _storedVerificationData = storedVerificationData[
                _encryptedKey
            ];
        if (
            keccak256(abi.encodePacked(_storedVerificationData.userName)) ==
            keccak256(abi.encodePacked(_userName))
        ) {
            emit VerificationErrorMessage(
                "User already exists, please change the userName"
            );
            return false;
        }

        storedVerificationData[_encryptedKey] = StoredVerificationData(
            _userName,
            _mutableDataHash,
            _immutableDataHash,
            block.timestamp,
            0
        );

        emit VerificationDataStored(
            _userName,
            _mutableDataHash,
            _immutableDataHash,
            block.timestamp,
            0
        );
        return true;
    }

    /**
     * @dev This function is used to verify the user
     * @param _userEncryptedKey Encrypted key of the user
     * @param _userName User name of the user
     * @param _mutableDataHash Chameleon hash of the mutable data
     * @param _immutableDataHash Hash of the immutable data
     * @return bool Returns true if the user is verified successfully
     */
    function verifyUserIdentity(
        string memory _userEncryptedKey,
        string memory _userName,
        string memory _mutableDataHash,
        string memory _immutableDataHash
    ) public view returns (bool) {
        string memory _encryptedKey = string(
            abi.encodePacked(_userEncryptedKey, verifierEncryptedKey, _userName)
        );
        StoredVerificationData
            memory _storedVerificationData = storedVerificationData[
                _encryptedKey
            ];

        if (
            keccak256(abi.encodePacked(_storedVerificationData.userName)) ==
            keccak256(abi.encodePacked(_userName)) &&
            keccak256(
                abi.encodePacked(_storedVerificationData.mutableDataHash)
            ) ==
            keccak256(abi.encodePacked(_mutableDataHash)) &&
            keccak256(
                abi.encodePacked(_storedVerificationData.immutableDataHash)
            ) ==
            keccak256(abi.encodePacked(_immutableDataHash))
        ) return true;

        return false;
    }

    /**
     * @dev This function is used to delete the verification data of the user
     * @param _userEncryptedKey Encrypted key of the user
     * @param _userName User name of the user
     * @return bool Returns true if the data is deleted successfully
     */
    function deleteVerificationData(
        string memory _userEncryptedKey,
        string memory _userName
    ) public onlyVerifier returns (bool) {
        string memory _encryptedKey = string(
            abi.encodePacked(_userEncryptedKey, verifierEncryptedKey, _userName)
        );
        StoredVerificationData
            memory _storedVerificationData = storedVerificationData[
                _encryptedKey
            ];
        if (
            keccak256(abi.encodePacked(_storedVerificationData.userName)) ==
            keccak256(abi.encodePacked(_userName))
        ) {
            delete storedVerificationData[_encryptedKey];
            emit VerificationDataDeleted(_userName);
            return true;
        }

        emit VerificationErrorMessage("User does not exist");
        return false;
    }

    /**
     * @dev This function is used to change the encrypted key or the userName of the user
     * @param _userEncryptedKey Encrypted key of the user
     * @param _newUserEncryptedKey New encrypted key of the user
     * @param _userName User name of the user
     * @return bool Returns true if the data is updated successfully
     */
    function changeUserEncryptionKey(
        string memory _userEncryptedKey,
        string memory _newUserEncryptedKey,
        string memory _userName
    ) public onlyVerifier returns (bool) {
        string memory _encryptedKey = string(
            abi.encodePacked(_userEncryptedKey, verifierEncryptedKey, _userName)
        );
        StoredVerificationData
            memory _storedVerificationData = storedVerificationData[
                _encryptedKey
            ];

        // If user has updated the data more than 5 times or the data is updated within 1 day
        if (
            _storedVerificationData.changeCount > 5 ||
            _storedVerificationData.updatedAt + 1 days > block.timestamp
        ) {
            emit VerificationErrorMessage(
                "User has updated the data more than 5 times or the data is updated within 1 day"
            );
            return false;
        }

        if (
            keccak256(abi.encodePacked(_storedVerificationData.userName)) ==
            keccak256(abi.encodePacked(_userName))
        ) {
            bool _isUserExists = verifyUserIdentity(
                _userEncryptedKey,
                _userName,
                _storedVerificationData.mutableDataHash,
                _storedVerificationData.immutableDataHash
            );
            if (!_isUserExists) {
                emit VerificationErrorMessage("User does not exist");
                return false;
            }

            bool _isDeleted = deleteVerificationData(
                _userEncryptedKey,
                _userName
            );
            if (!_isDeleted) {
                emit VerificationErrorMessage(
                    "User data is not deleted successfully"
                );
                return false;
            }

            bool _isStored = storeVerificationData(
                _userName,
                _storedVerificationData.mutableDataHash,
                _storedVerificationData.immutableDataHash,
                _newUserEncryptedKey,
                _storedVerificationData.changeCount + 1
            );
            if (!_isStored) {
                emit VerificationErrorMessage(
                    "User data is not stored successfully"
                );
                return false;
            }

            emit VerificationChangeEncryptionKey(
                _newUserEncryptedKey,
                _userEncryptedKey,
                _userName
            );
            return true;
        }
        return false;
    }

    /**
     * @dev This function is to reduce the count of the changeCount
     * @param _userEncryptedKey Encrypted key of the user
     * @param _userName User name of the user
     * @param _reduceCountTo The count to which the changeCount should be reduced
     * @return bool Returns true if the count is reduced successfully
     */
    function reduceChangeCount(
        string memory _userEncryptedKey,
        string memory _userName,
        uint256 _reduceCountTo
    ) public onlyVerifier returns (bool) {
        string memory _encryptedKey = string(
            abi.encodePacked(_userEncryptedKey, verifierEncryptedKey, _userName)
        );
        StoredVerificationData
            memory _storedVerificationData = storedVerificationData[
                _encryptedKey
            ];

        if (
            keccak256(abi.encodePacked(_storedVerificationData.userName)) ==
            keccak256(abi.encodePacked(_userName))
        ) {
            storedVerificationData[_encryptedKey] = StoredVerificationData(
                _userName,
                _storedVerificationData.mutableDataHash,
                _storedVerificationData.immutableDataHash,
                block.timestamp,
                _reduceCountTo
            );

            emit VerificationChangeCountReduced(_userName, _reduceCountTo);
            return true;
        }
        emit VerificationErrorMessage("User does not exist");
        return false;
    }
}
