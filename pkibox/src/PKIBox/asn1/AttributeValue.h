
#ifndef PKIBOX_ASN1_ATTRIBUTE_VALUE_H
#define PKIBOX_ASN1_ATTRIBUTE_VALUE_H

typedef struct asn1_type_st ASN1_TYPE;

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
	}

	namespace pkcs12
	{
		class CKeyBag;
		class CSecretBag;
	}

	namespace asn1
	{
		//! This class is the basic implementation for Attribute Values. Any class which implements some specific Attribute Value must be derived from this class. 
		/*!
			An Attribute consists of an attribute type (specified by an object identifier) and one or 
			more attribute values: 

			Attribute ::= SEQUENCE {
				type    AttributeType,
				values  SET OF AttributeValue -- at least one value is required --}

			AttributeType           ::=   OBJECT IDENTIFIER
			AttributeValue          ::=   ANY DEFINED BY type
		*/
		class AttributeValue
		{
			friend class pkcs12::CKeyBag;
			friend class pkcs12::CSecretBag;
			friend class Attribute;

		public:

			enum _ASN1_TYPE
			{
				_ASN1_BOOLEAN,
				_ASN1_STRING,
				_ASN1_OBJECT,
				_ASN1_INTEGER,
				_ASN1_ENUMERATED,
				_ASN1_BIT_STRING,
				_ASN1_OCTET_STRING,
				_ASN1_PRINTABLESTRING,
				_ASN1_T61STRING,
				_ASN1_IA5STRING,
				_ASN1_GENERALSTRING,
				_ASN1_BMPSTRING,
				_ASN1_UNIVERSALSTRING,
				_ASN1_UTCTIME,
				_ASN1_GENERALIZEDTIME,
				_ASN1_VISIBLESTRING,
				_ASN1_UTF8STRING,
			};

			//! Default constructor.
			AttributeValue(void);

			//! Creates AttributeValue of a certain ASN.1 type.
			/*!
				\param _ASN1_TYPE type: type of an attribute value
				\param void *pValue: value of an attribute
			*/
			AttributeValue(_ASN1_TYPE type, void *pValue);

			virtual ~AttributeValue(void);

			//! Copy constructor.
			/*!
				\param const AttributeValue &rhs
			*/
			AttributeValue(const AttributeValue &rhs);

			//! Copy assignment operator.
			/*!
				\param const AttributeValue &rhs
				\return AttributeValue &
			*/
			AttributeValue &operator=(const AttributeValue &rhs);

			//! Returns bytes of this AttributeValue.
			/*!
				\return utils::ByteArray: binary representation of attribute value
			*/
			utils::ByteArray GetBytes() const;

		protected:
			ASN1_TYPE	*m_pAttValue;
		};
	}
}

#endif // !PKIBOX_ASN1_ATTRIBUTE_VALUE_H

