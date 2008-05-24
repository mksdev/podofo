
#ifndef PKIBOX_X509_EXTENSIONS_CERTIFICATE_POLICIES_H
#define PKIBOX_X509_EXTENSIONS_CERTIFICATE_POLICIES_H

#include <vector>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			class PolicyInformation;

			//! This class represents CertificatePolicies extension.
			/*!
				certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

				PolicyInformation ::= SEQUENCE {
					policyIdentifier   CertPolicyId,
					policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }

				CertPolicyId ::= OBJECT IDENTIFIER

				PolicyQualifierInfo ::= SEQUENCE {
					policyQualifierId   PolicyQualifierId,
					qualifier           ANY DEFINED BY policyQualifierId }

				Qualifier ::= CHOICE {
					cPSuri         CPSuri,     -- CPS Pointer qualifier
					userNotice     UserNotice  -- User Notice qualifier
				}

				CPSuri ::= IA5String

				UserNotice ::= SEQUENCE {
					noticeRef     NoticeReference OPTIONAL,
					explicitText  DisplayText OPTIONAL}

				NoticeReference ::= SEQUENCE {
					organization  DisplayText,
					noticeNumbers SEQUENCE OF INTEGER }

				DisplayText ::= CHOICE {
					visibleString    VisibleString  (SIZE (1..200)),
					bmpString        BMPString      (SIZE (1..200)),
					utf8String       UTF8String     (SIZE (1..200)) }
			*/
			class CertificatePolicies : public x509::X509Extension
			{
			public:
				//! Default Constructor. Creates an empty CertificatePolicies.
				CertificatePolicies(void);

				virtual ~CertificatePolicies(void);

				//! Creates a Certificate Policy object from the given Policy Information.
				/*!
					\param const std::vector<PolicyInformation> &vPolicyInformation: one or more certificate policy informations
				*/
				CertificatePolicies(const std::vector<PolicyInformation> &vPolicyInformation);

				//! Returns the Certificate Policies. 
				/*!
					\return std::vector<PolicyInformation>: the certificate policies
				*/
				std::vector<PolicyInformation> GetPolicyInformation() const; 
			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_CERTIFICATE_POLICIES_H

