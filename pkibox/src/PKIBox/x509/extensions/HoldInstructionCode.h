
#ifndef PKIBOX_X509_EXTENSIONS_HOLD_INSTRUCTION_CODE_H
#define PKIBOX_X509_EXTENSIONS_HOLD_INSTRUCTION_CODE_H

#include "../X509Extension.h"

namespace PKIBox
{
	namespace asn1
	{
		class ObjectID;
	}

	namespace x509
	{
		namespace extensions
		{
			//! This class implements the HoldInstructionCode extension. 
			/*!
				The HoldInstructionCode extension is a non-critical standard X509v2 CRL entry extension. 
				The ASN.1 definition of HoldInstructionCode is: 

				holdInstructionCode ::= OBJECT IDENTIFER
			*/
			class HoldInstructionCode : public x509::X509Extension
			{
			public:
				//! The holdinstruction-none oid (1.2.840.10040.2.1).  
				static asn1::ObjectID s_holdInstructionNone; 

				//! The holdinstruction-callissuer oid (1.2.840.10040.2.2).  
				static asn1::ObjectID s_holdInstructionCallIssuer; 

				//! The holdinstruction-reject oid (1.2.840.10040.2.3).  
				static asn1::ObjectID s_holdInstructionReject; 

				//! Default constructor.
				HoldInstructionCode(void);

				virtual ~HoldInstructionCode(void);

				//! Creates a new HoldInstructionCode from the given oid. 
				/*!
					\param const asn1::ObjectID &instructionCode: the hold instruction code oid
				*/
				explicit HoldInstructionCode(const asn1::ObjectID &instructionCode);

				//! Returns the hold instruction code. 
				/*!
					\return asn1::ObjectID: the hold instruction code
				*/
				asn1::ObjectID GetHoldInstructionCode() const;

				//! Sets the hold instruction code. 
				/*!
					\param const asn1::ObjectID &instructionCode: the hold instruction code
				*/
				void SetInstructionCode(const asn1::ObjectID &instructionCode);
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_HOLD_INSTRUCTION_CODE_H

