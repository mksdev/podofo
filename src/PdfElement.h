/***************************************************************************
 *   Copyright (C) 2006 by Dominik Seichter                                *
 *   domseichter@web.de                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef _PDF_ELEMENT_H_
#define _PDF_ELEMENT_H_

#include "PdfDefines.h"
#include "PdfObject.h"

namespace PoDoFo {

class PdfVecObjects;
class PdfVariant;

/** PdfElement is a common base class for all elements
 *  in a PDF file. For example pages, action and annotations.
 *
 *  Every PDF element has one PdfVariant (which may be a direct object or an
 *  indirect object of a real type based on PdfObject) and provides an easier
 *  interface to modify the contents of the dictionary. 
 *  
 *  A PdfElement base class can be created from an existing PdfVariant
 *  or created from scratch. In the later case, the PdfElement creates
 *  a new indirect object and adds it to a vector of objects.
 *
 *  A PdfElement cannot be created directly. Use one
 *  of the subclasses which implement real functionallity.
 *
 *  \see PdfPage \see PdfAction \see PdfAnnotation
 *
 * XXX TODO FIXME ownership/lifetime issues - if it's an indirect object, the
 * PdfVecObjects owns our contained variant - but what about direct objects?!
 */
class PODOFO_API PdfElement {

 public:

    virtual ~PdfElement();

    /** Get access to the internal object
     *  \returns the internal PdfVariant
     */
    inline PdfVariant* GetObject();

    /** Get access to the internal object
     *  This is an overloaded member function.
     *
     *  \returns the internal PdfVariant
     */
    inline const PdfVariant* GetObject() const;

 protected:
    /** Creates a new PdfElement with an indirect object.
     *
     *  \param pszType type entry of the elements object
     *  \param pParent parent vector of objects.
     *                 Add a newly created object to this vector.
     */
    PdfElement( const char* pszType, PdfVecObjects* pParent );

    /** Create a PdfElement from an existing PdfVariant
     *  \param pszType type entry of the elements object.
     *                 Throws an exception if the type in the 
     *                 PdfVariant differs from pszType.
     *  \param pObject pointer to the PdfVariant that is modified
     *                 by this PdfElement
     */
    PdfElement( const char* pszType, PdfVariant* pVariant );

    /** Convert an enum or index to its string representation
     *  which can be written to the PDF file.
     * 
     *  This is a helper function for various PdfElement 
     *  subclasses that need strings and enums for their
     *  SubTypes keys.
     *
     *  \param i the index or enum value
     *  \param ppTypes an array of strings containing
     *         the string mapping of the index
     *  \param lLen the length of the string array
     *
     *  \returns the string representation or NULL for 
     *           values out of range
     */
    const char* TypeNameForIndex( int i, const char** ppTypes, long lLen ) const;

    /** Convert a string type to an array index or enum.
     * 
     *  This is a helper function for various PdfElement 
     *  subclasses that need strings and enums for their
     *  SubTypes keys.
     *
     *  \param pszType the type as string
     *  \param ppTypes an array of strings containing
     *         the string mapping of the index
     *  \param lLen the length of the string array
     *
     *  \returns the index of the string in the array
     */
    int TypeNameToIndex( const char* pszType, const char** ppTypes, long lLen ) const;

 private:
    // Access this member through GetObject() so subclasses can properly
    // control the return type.
    PdfVariant* m_pVariant;
};


// -----------------------------------------------------
// 
// -----------------------------------------------------
inline PdfVariant* PdfElement::GetObject()
{
    return m_pVariant;
}

// -----------------------------------------------------
// 
// -----------------------------------------------------
inline const PdfVariant* PdfElement::GetObject() const
{
    return m_pVariant;
}

class PdfObject;

/**
 * PdfIElement is a PdfElement that may only refer to an indirect object.
 * It ensures that it only ever contains an indirect object, and works with
 * PdfObject rather than PdfVariant.
 */
class PdfIElement : public PdfElement
{

 public:

    virtual ~PdfIElement();

    /**
     * We know that our object is always indirect, so we can return a PdfObject*
     * to GetObject() .
     */
    inline PdfObject* GetObject();

    /**
     * We know that our object is always indirect, so we can return a PdfObject*
     * to GetObject() .
     */
    inline const PdfObject* GetObject() const;

 protected:
    /** Creates a new PdfIElement with an indirect object.
     *
     *  \param pszType type entry of the elements object
     *  \param pParent parent vector of objects.
     *                 Add a newly created object to this vector.
     */
    PdfIElement( const char* pszType, PdfVecObjects* pParent )
        : PdfElement( pszType, pParent)
    {
    }

    /** Create a PdfElement from an existing PdfVariant
     *  \param pszType type entry of the elements object.
     *                 Throws an exception if the type in the 
     *                 PdfVariant differs from pszType.
     *  \param pObject pointer to the PdfVariant that is modified
     *                 by this PdfElement
     */
    PdfIElement( const char* pszType, PdfObject* pObject )
        : PdfElement( pszType, pObject )
    {
    }
};

// -----------------------------------------------------
// 
// -----------------------------------------------------
inline PdfObject* PdfIElement::GetObject()
{
    // XXX TODO Ensure really PdfObject if debugging on
    return static_cast<PdfObject*>( PdfElement::GetObject() );
}

// -----------------------------------------------------
// 
// -----------------------------------------------------
inline const PdfObject* PdfIElement::GetObject() const
{
    // XXX TODO Ensure really PdfObject if debugging on
    return static_cast<const PdfObject*>( PdfElement::GetObject() );
}

};

#endif // PDF_ELEMENT_H_
