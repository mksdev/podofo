
#ifndef PKIBOX_X509_EXTENSIONS_POLICY_INFORMATION_H
#define PKIBOX_X509_EXTENSIONS_POLICY_INFORMATION_H

typedef struct POLICYINFO_st POLICYINFO;

#include <vector>

namespace PKIBox
{
	namespace asn1
	{
		class ObjectID;
	}

	namespace cms
	{
		namespace ess
		{
			class CSigningCertificate;
		}
	}

	namespace x509
	{
		namespace extensions
		{
			class PolicyQualifierInfo;

			//! This class represents the PolicyInformation in CertificatePolicies Extension.
			/*!
				PolicyInformation ::= SEQUENCE {
					policyIdentifier   CertPolicyId,
					policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }

				CertPolicyId ::= OBJECT IDENTIFIER

				PolicyQualifierInfo ::= SEQUENCE {
					policyQualifierId   PolicyQualifierId,
					qualifier           ANY DEFINED BY policyQualifierId }

				Qualifier ::= CHOICE {
					cPSuri         CPSuri,     -- CPS Pointer qualifier
					userNotice     UserNotice  -- User Notice qualifier	}

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
			class PolicyInformation
			{
				friend class CertificatePolicies;
				friend class cms::ess::CSigningCertificate;

			public:
				//! Default constructor. Creates an empty object of PolicyInformation
				PolicyInformation(void);

				virtual ~PolicyInformation(void);

				//! Creates a new PolicyInformation object from given policy id and policy qualifiers.
				/*!
					\param const asn1::ObjectID &OID: the id of the policy
					\param const std::vector<PolicyQualifierInfo> &vecPolicyQualifierInfo: zero ore more qualifiers
				*/
				PolicyInformation(const asn1::ObjectID &OID, const std::vector<PolicyQualifierInfo> &vecPolicyQualifierInfo );

				//! Copy Constructor
				/*!
					\param const PolicyInformation &PolicyInfo
				*/
				PolicyInformation(const PolicyInformation &PolicyInfo);

				//! Copy assignment operator.
				/*!
					\param const PolicyInformation &rhs
					\return PolicyInformation &
				*/
				PolicyInformation &operator=(const PolicyInformation &rhs);

				//! Returns the policy identifier. 
				/*!
					\return asn1::ObjectID: the policy identifier
				*/
				asn1::ObjectID GetPolicyIdentifier()const;

				//! Returns the policy qualifiers. 
				/*!
					\return std::vector<PolicyQualifierInfo>: the policy qualifiers
				*/
				std::vector<PolicyQualifierInfo> GetPolicyQualifiers()const;

			private:
				POLICYINFO * m_pPolicyInfo;
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_POLICY_INFORMATION_H

