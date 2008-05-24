
#include "PublicKey.h"

//-------------- OpenSSL Includes ------------------------
#include <openssl/err.h>
#include <openssl/pem.h>

#include <cassert>
#include "../Exception.h"
#include "../NullPointerException.h"
#include "../InvalidArgumentException.h"
#include "../utils/ByteArray.h"

using namespace std;

namespace PKIBox
{
	namespace x509
	{
		//---------------------------------------------------------------------------------------
		// Function name	: PublicKey()
		// Description	    : Default Constructor. Initializes m_pKey to NULL.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		PublicKey::PublicKey() : m_pKey(NULL)
		{

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool PublicKey::IsDER(const unsigned char *pbArray)
		{
			assert(pbArray != NULL);
			return pbArray[0] == '0' ? true : false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void PublicKey::Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (Exception) */ 
		{
			assert(pbArray != NULL);
			assert(cLength > 0);

			if(IsDER(pbArray)) // DER
			{
				m_pKey = ::d2i_PublicKey(EVP_PK_RSA, NULL, &pbArray, cLength);
				if(!m_pKey)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
				pbArray -= cLength;
			}
			else // PEM
			{
				BIO *pBIO = ::BIO_new(BIO_s_mem());
				if(!pBIO)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int iRet = ::BIO_write(pBIO, pbArray, cLength);

				m_pKey = PEM_read_bio_PUBKEY(pBIO, NULL, NULL, NULL);
				if(!m_pKey)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					iRet = ::BIO_free(pBIO);
					throw Exception(pc);
				}

				iRet = ::BIO_free(pBIO);
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKey::PublicKey(const utils::ByteArray &pk) : m_pKey( NULL )
		{
			if(pk.IsEmpty())
			{
				throw InvalidArgumentException("The provided byte array is empty.");
			}

			unsigned char *puc = const_cast<unsigned char *>( pk.GetData() );
			unsigned int uiSize = pk.GetLength();
			Construct(puc, uiSize);
		}



		//---------------------------------------------------------------------------------------
		// Function name	: ~PublicKey()
		// Description	    : Destructor.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		/*virtual*/ PublicKey::~PublicKey()
		{
			if(m_pKey)
			{
				::EVP_PKEY_free(m_pKey);
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKey::PublicKey(const PublicKey &rhs)
		{
			CRYPTO_add(& rhs.m_pKey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			m_pKey = rhs.m_pKey;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		PublicKey &PublicKey::operator=(const PublicKey &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if(m_pKey)
			{
				::EVP_PKEY_free(m_pKey);
			}

			// Assign new values
			CRYPTO_add(& rhs.m_pKey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			m_pKey = rhs.m_pKey;

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: GetAlgorithm()
		// Description	    : Returns algorithm name of this PublicKey as string.
		// Return type		: string
		//						Algorithm name of this PublicKey.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		string PublicKey::GetAlgorithm() const /* throw (Exception) */
		{
			if(!m_pKey)
				throw NullPointerException("There is no PublicKey to get Algorithm from.");

			int iType = ::EVP_PKEY_type(m_pKey->save_type);

			switch(iType)
			{
			case EVP_PKEY_RSA:
				return "RSA";

			case EVP_PKEY_DSA:
				return "DSA";

			case EVP_PKEY_DH:
				return "DH";

			default:
				return "Unknown";
			}

		}

		//---------------------------------------------------------------------------------------
		// Function name	: GetAlgorithm()
		// Description	    : Returns algorithm name of this PublicKey as string.
		// Return type		: string
		//						Algorithm name of this PublicKey.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		string PublicKey::GetAlgorithmName() const /* throw (Exception) */
		{
			if(!m_pKey)
				throw NullPointerException("There is no PublicKey to get Algorithm name from.");

			int iType = ::EVP_PKEY_type(m_pKey->save_type);

			switch(iType)
			{
			case EVP_PKEY_RSA:
				return "RSA";

			case EVP_PKEY_DSA:
				return "DSA";

			case EVP_PKEY_DH:
				return "DH";

			default:
				return "Unknown";
			}
		}
		

		//---------------------------------------------------------------------------------------
		// Function name	: GetEncoded()
		// Description	    : Returns the encoding form of this PublicKey.
		// Return type		: auto_ptr<ByteArray>
		//						Smart pointer to ByteArray containing binary encoding of PublicKey.
		// Argument         : Nothing.
		//---------------------------------------------------------------------------------------
		utils::ByteArray PublicKey::GetEncoded() const /* throw (Exception) */
		{
			if(!m_pKey)
				throw NullPointerException("There is no PublicKey to get in encoded form.");

			utils::ByteArray ba;
			int iSize = ::i2d_PublicKey(m_pKey, NULL);
			if(iSize == -1)
			{
				return ba; // Return empty ByteArray.
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
			iSize = ::i2d_PublicKey(m_pKey, &pEncoded);
			pEncoded -= iSize;

			ba.Set(pEncoded, iSize);

			::free(pEncoded);  // Deallocate

			return ba;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: ToPEM()
		// Description	    : Returns the pem encoding form of this PublicKey.
		// Return type		: ByteArray
		//						ByteArray containing pem encoding of PublicKey.
		// Argument         : Nothing.
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		utils::ByteArray PublicKey::ToPEM ()const /* throw (Exception) */
		{
			if(!m_pKey)
				throw NullPointerException("There is no PublicKey to get in PEM form.");

			BIO *pBIO = ::BIO_new(BIO_s_mem());
			PEM_write_bio_PUBKEY(pBIO, m_pKey);

			char *pBuffer = NULL;
			long lSize = BIO_get_mem_data(pBIO, &pBuffer);

			utils::ByteArray ba(reinterpret_cast<unsigned char *>(pBuffer), lSize);
			int iRet = ::BIO_free(pBIO);

			return ba;

		}
	}
}

