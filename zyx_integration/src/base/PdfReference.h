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

#ifndef _PDF_REFERENCE_H_
#define _PDF_REFERENCE_H_

#include "PdfDefines.h"

#include "PdfDataType.h"

namespace PoDoFo {

typedef pdf_uint32 pdf_objnum;
/* Technically a generation number must be able to represent 99999 so 65535 isn't good enough.
 * In practice Adobe's implementation notes suggest that they use a uint16 internally, and PDFs
 * with greater object numbers won't work on many viewers. So we'll stick with uint16.
 *
 * If you change this you'll need to change PdfReference::Write(...) to use the apppropriate
 * format, too. */
typedef pdf_uint16 pdf_gennum;

class PdfOutputDevice;

/**
 * A reference is a pointer to a object in the PDF file of the form
 * "4 0 R", where 4 is the object number and 0 is the generation number.
 * Every object in the PDF file can be indetified this way.
 *
 * This class is a indirect reference in a PDF file.
 */
class PODOFO_API PdfReference : public PdfDataType {
 public:
    /**
     * Create a PdfReference with object number and generation number
     * initialized to 0.
     */
    PdfReference();

    /**
     * Create a PdfReference to an object with a given object and generation number.
     *
     * \param nObjectNo the object number
     * \param nGenerationNo the generation number
     */
    PdfReference( const pdf_objnum nObjectNo, const pdf_gennum nGenerationNo );

    /**
     * Create a copy of an existing PdfReference.
     * 
     * \param rhs the object to copy
     */
    PdfReference( const PdfReference & rhs );

    PODOFO_NOTHROW virtual ~PdfReference();

    /** Convert the reference to a string.
     *  \returns a string representation of the object.
     *
     *  \see PdfVariant::ToString
     */
    const std::string ToString() const;

   /**
     * Assign the value of another object to this PdfReference.
     *
     * \param rhs the object to copy
     */
    PODOFO_NOTHROW const PdfReference & operator=( const PdfReference & rhs );

    /** Write the complete variant to an output device.
     *  This is an overloaded member function.
     *
     *  \param pDevice write the object to this device
     *  \param eWriteMode additional options for writing this object
     *  \param pEncrypt an encryption object which is used to encrypt this object
     *                  or NULL to not encrypt this object
     */
    void Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, const PdfEncrypt* pEncrypt = NULL ) const;

    /** 
     * Compare to PdfReference objects.
     * \returns true if both reference the same object
     */
    PODOFO_NOTHROW bool operator==( const PdfReference & rhs ) const;

    /** 
     * Compare to PdfReference objects.
     * \returns false if both reference the same object
     */
    PODOFO_NOTHROW bool operator!=( const PdfReference & rhs ) const;

    /** 
     * Compare to PdfReference objects.
     * \returns true if this reference has a smaller object and generation number
     */
    PODOFO_NOTHROW bool operator<( const PdfReference & rhs ) const;

    /** Set the object number of this object
     *  \param o the new object number
     */
    PODOFO_NOTHROW void SetObjectNumber( pdf_objnum o );

    /** Get the object number.
     *  \returns the object number of this PdfReference
     */
    PODOFO_NOTHROW pdf_objnum ObjectNumber() const;

    /** Set the generation number of this object
     *  \param g the new generation number
     */
    PODOFO_NOTHROW void SetGenerationNumber( const pdf_gennum g );

    /** Get the generation number.
     *  \returns the generation number of this PdfReference
     */
    PODOFO_NOTHROW pdf_gennum GenerationNumber() const;

    /** Allows to check if a reference points to an indirect
     *  object.
     *
     *  A reference is indirect if object number and generation
     *  number are both not equal 0.
     *
     *  \returns true if this reference is the reference of
     *           an indirect object.
     */
    PODOFO_NOTHROW bool IsIndirect() const;

 private:
    pdf_objnum    m_nObjectNo;
    pdf_gennum    m_nGenerationNo;
};

};

#endif // _PDF_REFERENCE_H_

