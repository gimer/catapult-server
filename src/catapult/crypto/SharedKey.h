/**
*** Copyright (c) 2016-present,
*** Jaguar0625, gimre, BloodyRookie, Tech Bureau, Corp. All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#pragma once
#include "KeyPair.h"

namespace catapult { namespace crypto {

	struct Salt_tag { static constexpr size_t Size = 32; };
	using Salt = utils::ByteArray<Salt_tag>;

	struct SharedSecret_tag { static constexpr size_t Size = 32; };
	using SharedSecret = utils::ByteArray<SharedSecret_tag>;

	struct SharedKey_tag { static constexpr size_t Size = 32; };
	using SharedKey = utils::ByteArray<SharedKey_tag>;

	void Hkdf_Hmac_Sha256(
			const  std::vector<uint8_t>& sharedSecret,
			const std::vector<uint8_t>& salt,
			std::vector<uint8_t>& output,
			const std::vector<uint8_t>& label);

	void KdfSp800_56C_Hmac_Sha256(
			const std::vector<uint8_t>& sharedSecret,
			const std::vector<uint8_t>& salt,
			std::vector<uint8_t>& output,
			const std::vector<uint8_t>& label);

	/// Generates shared key using \a keyPair, \a otherPublicKey and \a salt.
	SharedKey DeriveSharedKey(const KeyPair& keyPair, const Key& otherPublicKey, const Salt& salt);
}}
