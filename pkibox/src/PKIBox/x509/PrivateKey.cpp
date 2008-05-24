
#include "PrivateKey.h"

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
		// Function name	: PrivateKey()
		// Description	    : Default Constructor. Initializes m_pPrivateKey to NULL.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		PrivateKey::PrivateKey() : m_pPrivateKey( NULL )
		{

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool PrivateKey::IsDER(const unsigned char *pbArray)
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
		void PrivateKey::Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (Exception) */ 
		{
			assert(pbArray != NULL);
			assert(cLength > 0);

			if(IsDER(pbArray)) // DER
			{
				m_pPrivateKey = ::d2i_PrivateKey(EVP_PK_RSA, NULL, &pbArray, cLength);
				if(!m_pPrivateKey)
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

				m_pPrivateKey = PEM_read_bio_PrivateKey(pBIO, NULL, NULL, NULL);
				if(!m_pPrivateKey)
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
		PrivateKey::PrivateKey(const utils::ByteArray &pk) : m_pPrivateKey( NULL )
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
		// Function name	: PrivateKey()
		// Description	    : Copy constructor.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		PrivateKey::PrivateKey(const PrivateKey &rhs)
		{
			CRYPTO_add(& rhs.m_pPrivateKey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			m_pPrivateKey = rhs.m_pPrivateKey;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: PrivateKey()
		// Description	    : Copy Assignment operator.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		PrivateKey& PrivateKey::operator=(const PrivateKey &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if( m_pPrivateKey )
			{
				::EVP_PKEY_free( m_pPrivateKey );
			}

			// Assign new values
			CRYPTO_add(& rhs.m_pPrivateKey->references, 1, CRYPTO_LOCK_EVP_PKEY); 
			m_pPrivateKey = rhs.m_pPrivateKey;

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: PrivateKey()
		// Description	    : Returns algorithm name of this PublicKey as string.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		string PrivateKey::GetAlgorithm() const /* throw (NullPointerException) */
		{
			if( !m_pPrivateKey )
				throw NullPointerException("There is no PrivateKey to get Algorithm from.");

			int iType = ::EVP_PKEY_type( m_pPrivateKey->save_type );

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
		// Function name	: PrivateKey()
		// Description	    : Returns algorithm name of this PublicKey as string.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		string PrivateKey::GetAlgorithmName() const /* throw (NullPointerException) */
		{
			if( !m_pPrivateKey )
				throw NullPointerException("There is no PrivateKey to get Algorithm from.");

			int iType = ::EVP_PKEY_type( m_pPrivateKey->save_type );

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
		// Function name	: PrivateKey()
		// Description	    : Returns the encoding form of this PublicKey.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::ByteArray PrivateKey::GetEncoded() const /* throw (NullPointerException) */
		{
			if( !m_pPrivateKey )
				throw NullPointerException("There is no PrivateKey to get in encoded form.");

			utils::ByteArray ba;
			int iSize = ::i2d_PrivateKey( m_pPrivateKey, NULL );
			if(iSize == -1)
			{
				return ba; // Return empty ByteArray.
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc( iSize ); // Allocate
			iSize = ::i2d_PrivateKey( m_pPrivateKey, &pEncoded );
			pEncoded -= iSize;

			ba.Set( pEncoded, iSize );

			::free( pEncoded );  // Deallocate

			return ba;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: ~PrivateKey()
		// Description	    : Destructor
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		PrivateKey::~PrivateKey()
		{
			if ( m_pPrivateKey )
			{
				::EVP_PKEY_free( m_pPrivateKey );
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: ToPEM()
		// Description	    : Returns the pem encoding form of this PublicKey.
		// Return type		: ByteArray
		//						ByteArray containing pem encoding of PublicKey.
		// Argument         : Nothing.
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		utils::ByteArray PrivateKey::ToPEM ()const /* throw (NullPointerException) */
		{
			if(!m_pPrivateKey)
			{
				throw NullPointerException("There is no PrivateKey to get in PEM form.");
			}

			BIO *pBIO = ::BIO_new(BIO_s_mem());
			PEM_write_bio_PrivateKey(pBIO, m_pPrivateKey, NULL, NULL, NULL, NULL, NULL);

			char *pBuffer = NULL;
			long lSize = BIO_get_mem_data(pBIO, &pBuffer);

			utils::ByteArray ba(reinterpret_cast<unsigned char *>(pBuffer), lSize);
			int iRet = ::BIO_free(pBIO);

			return ba;

		}

	}
}

