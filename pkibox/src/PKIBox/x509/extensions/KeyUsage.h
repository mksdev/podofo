
#ifndef PKIBOX_X509_EXTENSIONS_KEY_USAGE_H
#define PKIBOX_X509_EXTENSIONS_KEY_USAGE_H

#include <bitset>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace x509
	{
		// Forward declarations.
		class CX509Extension;

		//! This namespace provides classes for processing of different X509 extensions.
		namespace extensions
		{
			//! This class represents the KeyUsage extension.
			/*! 
				ASN.1 definition of KeyUsage is

				KeyUsage ::= BIT STRING {<br>
					digitalSignature        (0),<br>
					nonRepudiation          (1),<br>
					keyEncipherment         (2),<br>
					dataEncipherment        (3),<br>
					keyAgreement            (4),<br>
					keyCertSign             (5),<br>
					cRLSign                 (6),<br>
					encipherOnly            (7),<br>
					decipherOnly            (8) }<br>
			*/
			class KeyUsage : public x509::X509Extension
			{
				friend class CX509Certificate;

			public:

				//! This enumeration represents the different key usages.
				enum KEYUSAGE 
				{ 
					digitalSignature = 0, 
					nonRepudiation, 
					keyEncipherment, 
					dataEncipherment, 
					keyAgreement,
					keyCertSign, 
					cRLSign, 
					encipherOnly, 
					decipherOnly 
				};

				//! This constant represents the number of key usages in KeyUsage extension.
				static const int NoofKeyUsages = 9;

				//! Default constructor. Creates an empty KeyUsage.
				KeyUsage(void);

				virtual ~KeyUsage(void);

				//! Return whether the specified key usage value is set.
				/*!
					\param const KEYUSAGE Index: keyUsage to be searched for
					\return bool: true if asked keyUsage present, false otherwise
				*/
				bool IsSet(const KEYUSAGE Index) const;

				//! Returns KeyUsage value in form of a bitset. 
				/*!
					\return std::bitset<NoofKeyUsages>: the key usage value as bitset representation
				*/
				std::bitset<NoofKeyUsages> GetKeyUsages();

				//! Sets KeyUsage value in form of a bitset.
				/*!
					\param const std::bitset<NoofKeyUsages> &keyUsage: the key usage value as bitset representation
				*/
				void SetKeyUsages(const std::bitset<NoofKeyUsages> &keyUsage) /* throw (CException)*/;

				//! Set the specific key usage specified by the KEYUSAGE index.
				/*!
					\param const KEYUSAGE Index: specific keyUsage to set
				*/
				void SetKeyUsage(const KEYUSAGE Index) const /* throw (CException)*/;

			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_KEY_USAGE_H

