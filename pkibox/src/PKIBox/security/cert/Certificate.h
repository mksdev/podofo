
#ifndef PKIBOX_SECURITY_CERT_CERTIFICATE_H
#define PKIBOX_SECURITY_CERT_CERTIFICATE_H

namespace PKIBox
{
	namespace security
	{
		//! This namespace provides classes to manipulate the security certificates
		namespace cert
		{
			//! Serves as base class for all kinds of certificates.
			class Certificate
			{
			public:		
				//! Default constructor
				Certificate();

				virtual ~Certificate();
			};
		}
	}
}

#endif // !PKIBOX_SECURITY_CERT_CERTIFICATE_H

