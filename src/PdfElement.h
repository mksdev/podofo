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
 *  in a PDF file. For example pages, action and annotations. It is used
 *  for classes in PoDoFo that provide friendlier interfaces to manipulate
 *  particular types of PDF constructs, such as pages or annotations, that're
 *  stored using underlying simple PDF data types.
 *
 *  Every PDF element has one PdfVariant (which may be a direct object or an
 *  indirect object of a type based on PdfObject) and provides an easier
 *  interface to modify the contents of the dictionary.  This variant is the
 *  underlying PDF data structure that the element is stored in.
 *  
 *  A PdfElement base class can be created from an existing PdfVariant
 *  or created from scratch. In the later case, the PdfElement creates
 *  a new indirect object and adds it to a vector of objects.
 *
 *  PdfElement never owns its associated variant. If an indirect object
 *  (a PdfObject) is used, the PdfVecObjects will hold ownership. For
 *  direct objects it is expected that the object's lifetime will be
 *  guaranteed by the user.
 *
 *  Copying a PdfElement does not copy the underlying object. The two
 *  copies share the underling object.
 *
 *  A PdfElement cannot be created directly. Use one
 *  of the subclasses which implement real functionallity.
 *
 *  \see PdfPage \see PdfAction \see PdfAnnotation
 */
class PODOFO_API PdfElement {

 public:

    virtual ~PdfElement();

    /** Get access to the internal object
     *
     *  We do not return a const variant, because this class is just
     *  a manipulator of the variant, which isn't part of the class.
     *  There are perfectly reasonable reasons to want access to a
     *  modifiable reference to the variant from a const object.
     *
     *  \returns the internal PdfVariant
     */
    inline PdfVariant* GetObject() const;

 protected:
    /** Creates a PdfElement with a new indirect object. The object
     *  will be owned by `pParent'.
     *
     *  \param pszType type entry of the elements object
     *  \param pParent parent vector of objects.
     *                 Add a newly created object to this vector.
     */
    PdfElement( const char* pszType, PdfVecObjects* pParent );

    /** Create a PdfElement from an existing PdfVariant.
     *  Ownership is not transferred, so the caller must
     *  ensure that the PdfVariant continues to exist.
     *
     *  \param pszType  type entry of the elements object.
     *                  Throws an exception if the type in the 
     *                  PdfVariant differs from pszType.
     *  \param pVariant pointer to the PdfVariant that is modified
     *                  by this PdfElement
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
    /** PdfElements do not support copying. Copying a PdfElement would
     *  not copy the underling variant, which will lead to problems.
     *  Just construct a new PdfElement from the same base variant
     *  if you really want this, but make sure the implementation
     *  can handle having the variant changed by things other than it.
     */
    PdfElement( const PdfElement& );

    /** PdfElements do not support assignment. */
    PdfElement & operator=( const PdfElement& );

    // Access this member through GetObject() so subclasses can properly
    // control the return type.
    // We DO NOT own the object pointed to here. It's lifetime must be
    // externally guaranteed by PdfVecObjects or the element's creator.
    PdfVariant * const m_pVariant;
};

// -----------------------------------------------------
// 
// -----------------------------------------------------
inline PdfVariant* PdfElement::GetObject() const
{
    return m_pVariant;
}

class PdfObject;

/**
 * PdfIElement is a PdfElement that may only refer to an indirect object.
 * It ensures that it only ever contains an indirect object, and works with
 * PdfObject rather than PdfVariant.
 *
 * PdfIElement never owns its associated variant. It's lifetime should be
 * managed by PdfVecObjects.
 */
class PdfIElement : public PdfElement
{

 public:

    virtual ~PdfIElement();

    /**
     * We know that our object is always indirect, so we can return a PdfObject*
     * to GetObject() .
     */
    inline PdfObject* GetObject() const;

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
 
 private:
    PdfIElement(const PdfIElement&);
    PdfIElement& operator=(const PdfIElement&);
};

// -----------------------------------------------------
// 
// -----------------------------------------------------
inline PdfObject* PdfIElement::GetObject() const
{
    return static_cast<const PdfObject*>( PdfElement::GetObject() );
}

};

#endif // PDF_ELEMENT_H_
