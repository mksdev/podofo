
#ifndef PKIBOX_X509_PUBLIC_KEY_H
#define PKIBOX_X509_PUBLIC_KEY_H

#include "../security/Key.h"

typedef struct evp_pkey_st EVP_PKEY;

#include <string>

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
	}

	namespace security
	{
		class CKeyPair;
		class CSignature;
		class IKey;
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
		class CBasicOCSPResponse;
	}

	namespace pkcs6
	{
		class CExtendedCertificate;
	}

	namespace pkcs7
	{
		class CSignedData;
	}

	namespace pkcs10
	{
		class CCertificateRequest;
	}

	namespace pkcs11
	{
		class CKey;
	}

	namespace cms
	{
		class CSignedData;
		class CCertfificateSet;
	}

	namespace pkcs1
	{
		class CRSACipher;
	}

	namespace x509
	{
		namespace attr
		{
			class CAttributeCertificate;
		}

		// Forward declarations.
		class X509Certificate;
		class PublicKeyInfo;

		//! This class implements a PublicKeyInfo as used within X.509 certificates for representing the subject´s public key.
		/*!
			The ASN.1 syntax of PublicKeyInfo is

			SubjectPublicKeyInfo  ::=  SEQUENCE  {<br>
				algorithm            AlgorithmIdentifier,<br>
				subjectPublicKey     BIT STRING  }<br>

			where: 

			AlgorithmIdentifier  ::=  SEQUENCE  {<br>
				algorithm               OBJECT IDENTIFIER,<br>
				parameters              ANY DEFINED BY algorithm OPTIONAL  }<br>
		*/
		class PublicKey : public security::IKey
		{
			friend class pkcs1::CRSACipher;
			friend class pkcs6::CExtendedCertificate;
			friend class X509Certificate;
			friend class X509CRL;
			friend class PublicKeyInfo;
			friend class ocsp::COCSPRequest;
			friend class ocsp::CBasicOCSPResponse;
			friend class pkcs7::CSignedData;
			friend class pkcs10::CCertificateRequest;
			friend class pkcs11::CKey;
			friend class attr::CAttributeCertificate;
			friend class cms::CSignedData;
			friend class cms::CCertfificateSet;
			friend class security::CKeyPair;
			friend class security::CSignature;
			friend class security::rsa::CRSAKeyPair;
			friend class security::dsa::CDSAKeyPair;

		public:
			//! Default constructor. Initializes m_pKey to NULL.
			PublicKey();

			virtual ~PublicKey();

			//! Creates a new PublicKey from a DER encoded ASN.1 data structure.  
			/*!
				\param const utils::ByteArray &pk: DER encoded ASN.1 data structure
			*/
			explicit PublicKey(const utils::ByteArray &pk);

			//! Copy constructor.
			/*!
				\param const PublicKey &rhs
			*/
			PublicKey(const PublicKey &rhs);

			//! Copy Assignment operator.
			/*!
				\param const PublicKey &rhs
				\return PublicKey &
			*/
			PublicKey &operator=(const PublicKey &rhs);

			//! Returns algorithm name of this PublicKey.
			/*!
				\return std::string: the name of the algorithm associated with this key
			*/
			std::string GetAlgorithm() const /* throw (Exception) */;

			//! Returns algorithm name of this PublicKey.
			/*!
				\return std::string: the name of the algorithm associated with this key
			*/
			std::string GetAlgorithmName() const /* throw (Exception) */;

			//! Returns the encoding form of this PublicKey.
			/*!
				\return utils::ByteArray: the encoded key, or null if the key does not support encoding
			*/
			utils::ByteArray GetEncoded() const /* throw (Exception) */;

			//! Returns the PEM encoding of this PublicKey. 
			/*!
				\return utils::ByteArray: Base64 encoding of this key
			*/
			utils::ByteArray ToPEM() const /* throw (Exception) */;

		protected:
			bool IsDER(const unsigned char *pbArray);
			void Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (Exception) */ ;

			EVP_PKEY *m_pKey; // Underlying OpenSSL PublicKey data structure.
		};
	}
}

#endif // !PKIBOX_X509_PUBLIC_KEY_H

