
#ifndef PKIBOX_X509_PRIVATE_KEY_H
#define PKIBOX_X509_PRIVATE_KEY_H

#include "../security/Key.h"

typedef struct evp_pkey_st EVP_PKEY;

#include <string>

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
	}

	namespace pkcs8
	{
		class CPrivateKeyInfo;
	}

	namespace pkcs10
	{
		class CCertificateRequest;
	}

	namespace security
	{
		class IKey;
		class CKeyPair;
		class CSignature;
		namespace rsa
		{
			class CRSAKeyPair;
		}
		namespace dsa
		{
			class CDSAKeyPair;
		}
	}

	namespace ocsp
	{
		class COCSPRequest;
	}

	namespace pkcs11
	{
		class CKey;
	}

	namespace pkcs12
	{
		class CPKCS12;
	}

	namespace pkcs7
	{
		class CSignerInfo;
		class CSignedData;
	}

	namespace pkcs1
	{
		class CRSACipher;
	}

	namespace x509
	{
		class PrivateKey : public security::IKey
		{
			friend class pkcs7::CSignerInfo;
			friend class pkcs7::CSignedData;
			friend class pkcs8::CPrivateKeyInfo;
			friend class pkcs10::CCertificateRequest;
			friend class pkcs11::CKey;
			friend class pkcs12::CPKCS12;
			friend class X509Certificate;
			friend class X509CRL;
			friend class security::CKeyPair;
			friend class security::CSignature;
			friend class security::rsa::CRSAKeyPair;
			friend class security::dsa::CDSAKeyPair;
			friend class ocsp::COCSPRequest;
			friend class pkcs1::CRSACipher;

		public:
			//! Default constructor. Initializes m_pPrivateKey to NULL.
			PrivateKey();

			//! Creates a new PrivateKey from a DER encoded ASN.1 data structure.  
			/*!
				\param const utils::ByteArray &pk: DER encoded ASN.1 data structure
			*/
			explicit PrivateKey(const utils::ByteArray &pk);
				
			//! Copy constructor.
			/*!
				\param const PrivateKey &rhs
			*/
			PrivateKey(const PrivateKey &rhs);

			//! Copy Assignment operator.
			/*!
				\param const PrivateKey &rhs
				\return PrivateKey &
			*/
			PrivateKey &operator=(const PrivateKey &rhs);

			//! Destructor
			virtual ~PrivateKey();

			//! Returns algorithm name of this PrivateKey.
			/*!
				\return std::string: the name of the algorithm associated with this key
			*/
			std::string GetAlgorithm() const /* throw (NullPointerException) */;

			//! Returns algorithm name of this PrivateKey.
			/*!
				\return std::string: the name of the algorithm associated with this key
			*/
			std::string GetAlgorithmName() const /* throw (NullPointerException) */;

			//! Returns the encoding form of this PrivateKey.
			/*!
				\return utils::ByteArray: the encoded key, or null if the key does not support encoding
			*/
			utils::ByteArray GetEncoded() const /* throw (NullPointerException) */;

			//! Returns the PEM encoding of this PrivateKey. 
			/*!
				\return utils::ByteArray: Base64 encoding of this key
			*/
			utils::ByteArray ToPEM() const;

		protected:
			bool IsDER(const unsigned char *pbArray);
			void Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (NullPointerException) */ ;

			EVP_PKEY* m_pPrivateKey; // Underlying OpenSSL PrivateKey data structure.
		};
	}

}

#endif // !PKIBOX_X509_PRIVATE_KEY_H
