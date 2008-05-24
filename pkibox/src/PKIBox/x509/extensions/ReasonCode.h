
#ifndef PKIBOX_X509_EXTENSION_REASON_CODE_H
#define PKIBOX_X509_EXTENSION_REASON_CODE_H

#include <string>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//! This class implements the ReasonCode extension. The ReasonCode extension is a non critical standard X509v2 CRL entry extension. 
			/*!
				The ASN.1 definition of ReasonCode is

				reasonCode ::= { CRLReason }

				CRLReason ::= ENUMERATED {
					unspecified             (0),
					keyCompromise           (1),
					cACompromise            (2),
					affiliationChanged      (3),
					superseded              (4),
					cessationOfOperation    (5),
					certificateHold         (6),
					removeFromCRL           (8),
					privilegeWithdrawn      (9),
					aACompromise           (10)}
			*/
			class ReasonCode : public x509::X509Extension
			{
			public:
				enum REASON_CODE
				{ 
					unspecified = 0, 
					keyCompromise, 
					cACompromise, 
					affiliationChanged, 
					superseded,
					cessationOfOperation, 
					certificateHold, 
					removeFromCRL = 8,
					privilegeWithdrawn,
					aACompromise
				};

				//! Default constructor. Constructs an empty ReasonCode object.
				ReasonCode(void);

				//! Constructs a ReasonCode from an integer.
				/*!
					\param int iReasonCode: the reason code specifying the reason for certificate revocation
				*/
				explicit ReasonCode(int iReasonCode);

				virtual ~ReasonCode(void);

				//! Returns the reason code specifying the reason for certificate revocation.
				/*!
					\return ReasonCode: the reason code
				*/
				REASON_CODE GetReasonCode() const;

				//! Returns the name of the reason code as string. 
				/*!
					\return std::string: the name of the reason code, e.g. "KeyCompromise"
				*/
				std::string GetReasonCodeString() const;

				//! Sets the reason code specifying the reason for certificate revocation.
				/*!
					\param const ReasonCode reasonCode: the reason code
				*/
				void SetReasonCode(const REASON_CODE reasonCode);

			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSION_REASON_CODE_H
