
#ifndef PKIBOX_X509_PUBLIC_KEY_INFO_H
#define PKIBOX_X509_PUBLIC_KEY_INFO_H

typedef struct X509_pubkey_st X509_PUBKEY;

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
	}

	namespace asn1
	{
		class AlgorithmID;
	}
	
	namespace x509
	{
		class PublicKey;

		//! This class implements a PublicKeyInfo as used within X.509 certificates for representing the subject´s public key in the SubjectPublicKeyInfo field
		/*!
			The subject´s public key is of type subjectPublicKeyInfo including a BIT-STRING representation of the public key together with an identification of the public-key algorithm being used, as defined in RFC 2459: 

			SubjectPublicKeyInfo  ::=  SEQUENCE  {
				algorithm            AlgorithmIdentifier,
				subjectPublicKey     BIT STRING  }

			where: 

			AlgorithmIdentifier  ::=  SEQUENCE  {
				algorithm               OBJECT IDENTIFIER,
				parameters              ANY DEFINED BY algorithm OPTIONAL  }
		*/
		class PublicKeyInfo
		{
		public:
			//! Default constructor.
			PublicKeyInfo(void);

			//! Copy constructor.
			/*!
				\param const PublicKeyInfo &rhs
			*/
			PublicKeyInfo(const PublicKeyInfo &rhs);

			//! Copy assignment operator.
			/*!
				\param const PublicKeyInfo &rhs
				\return PublicKeyInfo &
			*/
			PublicKeyInfo &operator=(const PublicKeyInfo &rhs);

			virtual ~PublicKeyInfo(void);

			//! Returns this PublicKeyInfo as a DER encoded ASN.1 data structure. 
			/*!
				\return utils::ByteArray: this PrivateKeyInfo as DER encoded byte array
			*/
			utils::ByteArray GetEncoded() const;

			//! Returns algorithm id. 
			/*!
				\return asn1::AlgorithmID: the AlgorithmID of the algorithm
			*/
			asn1::AlgorithmID GetAlgorithm() const;

			//! Returns raw public key contained in this PublicKeyInfo.
			/*!
				\return PublicKey: a RSAPublicKey, DSAPublicKey or DHPublicKey, depending on the AgorithmID inherent to the given ASN1Object
			*/
			PublicKey GetPublicKey() const;
				
		private:
			X509_PUBKEY		*m_pPublicKeyInfo; // Underlying OpenSSL struct.
		};
	}
}

#endif // !PKIBOX_X509_PUBLIC_KEY_INFO_H

