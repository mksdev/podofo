
#include "PublicKeyInfo.h"
#include "../openssl/Globals.h"
#include "../NullPointerException.h"
#include "../utils/ByteArray.h"
#include "../asn1/AlgorithmID.h"
#include "PublicKey.h"

using namespace PKIBox::utils;
using namespace PKIBox::asn1;


namespace PKIBox
{
	namespace x509
	{
		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKeyInfo::PublicKeyInfo(void) : m_pPublicKeyInfo(NULL)
		{

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKeyInfo::~PublicKeyInfo(void)
		{
			if(m_pPublicKeyInfo)
				::X509_PUBKEY_free(m_pPublicKeyInfo);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKeyInfo::PublicKeyInfo(const PublicKeyInfo &rhs) : m_pPublicKeyInfo(NULL)
		{
			m_pPublicKeyInfo = X509_PUBKEY_dup(rhs.m_pPublicKeyInfo);
			CRYPTO_add(& rhs.m_pPublicKeyInfo->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			m_pPublicKeyInfo->pkey = rhs.m_pPublicKeyInfo->pkey;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKeyInfo &PublicKeyInfo::operator=(const PublicKeyInfo &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;


			// delete already allocated memory
			if(m_pPublicKeyInfo)
				::X509_PUBKEY_free(m_pPublicKeyInfo);


			// Assign new values
			m_pPublicKeyInfo = X509_PUBKEY_dup(rhs.m_pPublicKeyInfo);
			CRYPTO_add(& rhs.m_pPublicKeyInfo->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			m_pPublicKeyInfo->pkey = rhs.m_pPublicKeyInfo->pkey;

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		ByteArray PublicKeyInfo::GetEncoded() const
		{
			if(!m_pPublicKeyInfo)
				throw NullPointerException("There is no PublicKeyInfo to get in encoded form");

			utils::ByteArray ba;
			int iSize = ::i2d_X509_PUBKEY(m_pPublicKeyInfo, NULL);
			if(iSize == -1)
			{
				return ba; // Return empty ByteArray.
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
			iSize = ::i2d_X509_PUBKEY(m_pPublicKeyInfo, &pEncoded);
			pEncoded -= iSize;

			ba.Set(pEncoded, iSize);

			::free(pEncoded);  // Deallocate

			return ba;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		AlgorithmID PublicKeyInfo::GetAlgorithm() const
		{
			if(!m_pPublicKeyInfo)
				throw NullPointerException("There is no PublicKeyInfo to get algorithm from");

			AlgorithmID algorithm;
			algorithm.m_pAlgID = X509_ALGOR_dup(m_pPublicKeyInfo->algor);
			return algorithm;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKey PublicKeyInfo::GetPublicKey() const
		{
			if(!m_pPublicKeyInfo)
				throw NullPointerException("There is no PublicKeyInfo to get subject public key from");

			PublicKey publicKey;
			CRYPTO_add(& m_pPublicKeyInfo->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			publicKey.m_pKey = m_pPublicKeyInfo->pkey;
			return publicKey;
		}

	}
}



