
#ifndef PKIBOX_X509_EXTENSIONS_BASIC_CONSTRAINTS_H
#define PKIBOX_X509_EXTENSIONS_BASIC_CONSTRAINTS_H

#include "../X509Extension.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//! This class represents the BasicConstraints extension.
			/*! 
				ASN.1 definition of BasicConstraints is

				basicConstraints EXTENSION ::= { <br>
					SYNTAX BasicConstraintsSyntax <br>
					IDENTIFIED BY id-ce-basicConstraints} <br>

				BasicConstraintsSyntax ::= SEQUENCE {<br>
					cA BOOLEAN DEFAULT FALSE<br>
					pathLenConstraint INTEGER (0..MAX) OPTIONAL	}<br>
			*/
			class BasicConstraints : public x509::X509Extension
			{
			public:
				//! Default constructor. Creates an empty BasicConstraints.
				BasicConstraints(void);

				virtual ~BasicConstraints(void);

				//! Returns true if the subject of the certificate holding this BasicConstraints extension is a CA.
				/*!
					\return bool: true if the subject is a CA, false if not
				*/
				bool GetCA() const;

				//! Sets the cA value of this BasicConstraints extension to true if the subject is a CA. 
				/*!
					\param bool bCA: the cA value, true if the subject is a CA
				*/
				void SetCA(bool bCA) /* throw (Exception)*/;

				//! Sets the pathLenConstraint value of this BasicConstraints extension specifying the maximum number of CA certificates that may follow the certificate in a certification path. 
				/*!
					\param int nPathLength: the pathLenConstraint value
				*/
				void SetPathLenConstraint(int nPathLength) /* throw (Exception) */;

				//! Returns the pathLenConstraint value of this BasicConstraints extension specifying the maximum number of CA certificates that may follow the certificate in a certification path.
				/*!
					\return int: the pathLenConstraint value specifying the maximum number of CA certificates that may follow the certificate in a certification path, or allowing any length of the certification path, if set to -1; only meaningful, if the cA value is set to true
				*/
				int GetPathLenConstraint() const;
			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_BASIC_CONSTRAINTS_H

